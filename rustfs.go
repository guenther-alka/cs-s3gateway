package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RustFS (like MinIO) stores an object as a folder  <bucket>/<key>/  with
//   xl.meta                 msgpack metadata (versions, sizes, ETag, content type, maybe the data itself = "inline")
//   <data-dir-uuid>/part.N  the data, in blocks of EcBSize bytes, every block prefixed by a 32 byte bitrot hash
// This file reads that layout read-only, for a RustFS data folder or the snapshots of it.
// Supported: one disk (data=1, parity=0), no compression, no encryption, latest version of an object.

const (
	kindPlain    = 0 // ordinary folder (also <dataset>/.zfs/snapshot)
	kindRust     = 1 // RustFS data folder: <bucket>/<object>
	kindRustSnap = 2 // snapshots of a RustFS data folder: <snapshot>/<bucket>/<object>

	bitrotHashLen = 32
	maxXLMeta     = 16 << 20
)

var errDeleteMarker = errors.New("latest version is a delete marker")

// errUnsupported is returned for objects the reader cannot decode (compressed, encrypted, striped over several disks ...).
type errUnsupported struct{ msg string }

func (e *errUnsupported) Error() string { return e.msg }

// ---------------------------------------------------------------- minimal msgpack decoder

type mpReader struct {
	b []byte
	i int
}

func (m *mpReader) need(n int) error {
	if n < 0 || m.i+n > len(m.b) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (m *mpReader) uint(n int) (uint64, error) {
	if err := m.need(n); err != nil {
		return 0, err
	}
	var v uint64
	for k := 0; k < n; k++ {
		v = v<<8 | uint64(m.b[m.i+k])
	}
	m.i += n
	return v, nil
}

func (m *mpReader) bin(n int) ([]byte, error) {
	if err := m.need(n); err != nil {
		return nil, err
	}
	v := m.b[m.i : m.i+n]
	m.i += n
	return v, nil
}

func (m *mpReader) arr(n, depth int) (any, error) {
	if n > len(m.b)-m.i { // every element needs at least one byte
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]any, 0, n)
	for k := 0; k < n; k++ {
		v, err := m.next(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (m *mpReader) mp(n, depth int) (any, error) {
	if 2*n > len(m.b)-m.i {
		return nil, io.ErrUnexpectedEOF
	}
	out := make(map[string]any, n)
	for k := 0; k < n; k++ {
		key, err := m.next(depth + 1)
		if err != nil {
			return nil, err
		}
		v, err := m.next(depth + 1)
		if err != nil {
			return nil, err
		}
		out[fmt.Sprint(key)] = v
	}
	return out, nil
}

func (m *mpReader) next(depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("msgpack nested too deep")
	}
	if err := m.need(1); err != nil {
		return nil, err
	}
	t := m.b[m.i]
	m.i++
	switch {
	case t <= 0x7f:
		return int64(t), nil
	case t >= 0xe0:
		return int64(int8(t)), nil
	case t&0xe0 == 0xa0:
		b, err := m.bin(int(t & 0x1f))
		return string(b), err
	case t&0xf0 == 0x90:
		return m.arr(int(t&0x0f), depth)
	case t&0xf0 == 0x80:
		return m.mp(int(t&0x0f), depth)
	}
	switch t {
	case 0xc0:
		return nil, nil
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	case 0xc4, 0xc5, 0xc6: // bin 8/16/32
		n, err := m.uint(1 << (t - 0xc4))
		if err != nil || n > math.MaxInt32 {
			return nil, io.ErrUnexpectedEOF
		}
		return m.bin(int(n))
	case 0xca:
		v, err := m.uint(4)
		return float64(math.Float32frombits(uint32(v))), err
	case 0xcb:
		v, err := m.uint(8)
		return math.Float64frombits(v), err
	case 0xcc, 0xcd, 0xce, 0xcf: // uint 8/16/32/64
		v, err := m.uint(1 << (t - 0xcc))
		return int64(v), err
	case 0xd0, 0xd1, 0xd2, 0xd3: // int 8/16/32/64
		w := 1 << (t - 0xd0)
		v, err := m.uint(w)
		return int64(v<<(64-8*uint(w))) >> (64 - 8*uint(w)), err
	case 0xd9, 0xda, 0xdb: // str 8/16/32
		n, err := m.uint(1 << (t - 0xd9))
		if err != nil || n > math.MaxInt32 {
			return nil, io.ErrUnexpectedEOF
		}
		b, err := m.bin(int(n))
		return string(b), err
	case 0xdc, 0xdd:
		n, err := m.uint(2 << (t - 0xdc))
		if err != nil || n > math.MaxInt32 {
			return nil, io.ErrUnexpectedEOF
		}
		return m.arr(int(n), depth)
	case 0xde, 0xdf:
		n, err := m.uint(2 << (t - 0xde))
		if err != nil || n > math.MaxInt32 {
			return nil, io.ErrUnexpectedEOF
		}
		return m.mp(int(n), depth)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext: type byte + 1/2/4/8/16 bytes
		_, err := m.bin(1 + 1<<(t-0xd4))
		return nil, err
	case 0xc7, 0xc8, 0xc9: // ext 8/16/32
		n, err := m.uint(1 << (t - 0xc7))
		if err != nil || n > math.MaxInt32 {
			return nil, io.ErrUnexpectedEOF
		}
		_, err = m.bin(1 + int(n))
		return nil, err
	}
	return nil, fmt.Errorf("unsupported msgpack type 0x%x", t)
}

func asInt(v any) (int64, bool) { n, ok := v.(int64); return n, ok }

func asBytes(v any) ([]byte, bool) { b, ok := v.([]byte); return b, ok }

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func asInts(v any) []int64 {
	a, _ := v.([]any)
	out := make([]int64, 0, len(a))
	for _, x := range a {
		n, _ := asInt(x)
		out = append(out, n)
	}
	return out
}

func uuidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
		}
	}
	if zero {
		return "null"
	}
	h := fmt.Sprintf("%x", b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ---------------------------------------------------------------- xl.meta

type xlObject struct {
	size      int64 // size of the object as the client sees it
	mtime     time.Time
	etag      string
	ctype     string
	ddir      string // data folder (uuid), empty for inline objects
	partNums  []int64
	partSizes []int64
	blockSize int64
	inline    []byte // bitrot framed data of an inline object
	unsupp    string // reason why the data cannot be decoded ("" = readable)
}

// parseXL decodes the newest version of an xl.meta file.
func parseXL(data []byte) (o *xlObject, err error) {
	defer func() {
		if r := recover(); r != nil {
			o, err = nil, fmt.Errorf("xl.meta: %v", r)
		}
	}()
	if len(data) < 16 || string(data[:4]) != "XL2 " {
		return nil, errors.New("xl.meta: not a version 2 file")
	}
	if binary.LittleEndian.Uint16(data[4:6]) != 1 {
		return nil, &errUnsupported{"xl.meta: unknown major version"}
	}
	m := &mpReader{b: data, i: 8}
	blobAny, err := m.next(0)
	if err != nil {
		return nil, fmt.Errorf("xl.meta: %w", err)
	}
	blob, ok := asBytes(blobAny)
	if !ok {
		return nil, errors.New("xl.meta: metadata block missing")
	}
	after := data[m.i:]
	if len(after) >= 5 && after[0] == 0xce { // crc32 of the metadata block
		after = after[5:]
	}
	inline := map[string][]byte{}
	if len(after) > 1 && after[0] == 1 { // inline data: version byte, then map versionID -> data
		im := &mpReader{b: after, i: 1}
		if v, err := im.next(0); err == nil {
			for k, x := range asMap(v) {
				if b, ok := asBytes(x); ok {
					inline[k] = b
				}
			}
		}
	}

	r := &mpReader{b: blob}
	for k := 0; k < 2; k++ { // header version, meta version
		if _, err := r.next(0); err != nil {
			return nil, fmt.Errorf("xl.meta: %w", err)
		}
	}
	nAny, err := r.next(0)
	n, _ := asInt(nAny)
	if err != nil || n < 0 || n > 100000 {
		return nil, errors.New("xl.meta: bad version count")
	}
	var bestMeta []byte
	var bestTime int64 = math.MinInt64
	bestType := int64(0)
	var bestVID string
	for k := int64(0); k < n; k++ {
		hAny, err1 := r.next(0)
		mAny, err2 := r.next(0)
		if err1 != nil || err2 != nil {
			return nil, errors.New("xl.meta: damaged version list")
		}
		hb, _ := asBytes(hAny)
		mb, _ := asBytes(mAny)
		hv, err := (&mpReader{b: hb}).next(0)
		h, _ := hv.([]any)
		if err != nil || len(h) < 4 {
			return nil, errors.New("xl.meta: damaged version header")
		}
		vid, _ := asBytes(h[0])
		mt, _ := asInt(h[1])
		typ, _ := asInt(h[3])
		if mt > bestTime { // newest wins, the first of equal ones (list is newest first)
			bestTime, bestMeta, bestType, bestVID = mt, mb, typ, uuidString(vid)
		}
	}
	if bestMeta == nil {
		return nil, errors.New("xl.meta: no version")
	}
	if bestType == 2 {
		return nil, errDeleteMarker
	}
	if bestType != 1 {
		return nil, &errUnsupported{"object has an old (legacy) format"}
	}
	mv, err := (&mpReader{b: bestMeta}).next(0)
	if err != nil {
		return nil, fmt.Errorf("xl.meta: %w", err)
	}
	v2 := asMap(asMap(mv)["V2Obj"])
	if v2 == nil {
		return nil, errors.New("xl.meta: object record missing")
	}
	o = &xlObject{}
	o.blockSize, _ = asInt(v2["EcBSize"])
	ecM, _ := asInt(v2["EcM"])
	ecN, _ := asInt(v2["EcN"])
	o.partNums = asInts(v2["PartNums"])
	o.partSizes = asInts(v2["PartSizes"])
	actual := asInts(v2["PartASizes"])
	o.size, _ = asInt(v2["Size"])
	if mt, ok := asInt(v2["MTime"]); ok {
		o.mtime = time.Unix(0, mt)
	}
	if dd, ok := asBytes(v2["DDir"]); ok {
		o.ddir = uuidString(dd)
	}
	sys, usr := asMap(v2["MetaSys"]), asMap(v2["MetaUsr"])
	o.etag, _ = usr["etag"].(string)
	o.ctype, _ = usr["content-type"].(string)
	if s, ok := asBytes(sys["x-rustfs-internal-actual-size"]); ok {
		if n, err := strconv.ParseInt(string(s), 10, 64); err == nil {
			o.size = n
		}
	} else if s, ok := asBytes(sys["x-minio-internal-actual-size"]); ok {
		if n, err := strconv.ParseInt(string(s), 10, 64); err == nil {
			o.size = n
		}
	}

	// what the reader cannot decode: still listed, but the download is refused with a clear message
	for _, mm := range []map[string]any{sys, usr} {
		for k := range mm {
			lk := strings.ToLower(k)
			switch {
			case strings.Contains(lk, "compression"):
				o.unsupp = "object is stored compressed by RustFS"
			case strings.Contains(lk, "encryption"):
				o.unsupp = "object is stored encrypted by RustFS"
			case strings.Contains(lk, "transition-status") || strings.Contains(lk, "transitioned"):
				o.unsupp = "object was moved to a remote tier"
			}
		}
	}
	if o.unsupp == "" && (ecM != 1 || ecN != 0 || len(asInts(v2["EcDist"])) > 1) {
		o.unsupp = fmt.Sprintf("object is erasure coded over several disks (data %d, parity %d): the shards of the other disks are needed", ecM, ecN)
	}
	if o.unsupp == "" {
		if o.blockSize <= 0 || len(o.partNums) != len(o.partSizes) || len(o.partSizes) != len(actual) {
			return nil, errors.New("xl.meta: inconsistent part list")
		}
		var sum int64
		for i, s := range o.partSizes {
			if s < 0 || s != actual[i] {
				o.unsupp = "object parts are transformed (compressed or encrypted)"
			}
			sum += s
		}
		if o.unsupp == "" && sum != o.size {
			return nil, errors.New("xl.meta: part sizes do not add up")
		}
	}
	if o.unsupp == "" {
		if _, isInline := sys["x-rustfs-internal-inline-data"]; isInline || sys["x-minio-internal-inline-data"] != nil {
			d, ok := inline[bestVID]
			if !ok {
				return nil, errors.New("xl.meta: inline data missing")
			}
			o.inline = d
			o.ddir = ""
		} else if o.ddir == "" && o.size > 0 {
			return nil, errors.New("xl.meta: data folder missing")
		}
	}
	return o, nil
}

// ---------------------------------------------------------------- data reader

type rustPart struct {
	num   int64
	size  int64 // data bytes of the part
	start int64 // offset of the part in the object
}

// rustReader implements io.ReaderAt over the bitrot framed blocks of all parts (hashes are skipped, not verified).
type rustReader struct {
	b      *bucket
	dir    string // object folder, slash separated, relative to the bucket root
	ddir   string
	parts  []rustPart
	size   int64
	bs     int64
	inline []byte

	mu     sync.Mutex
	cur    *os.File
	curNum int64
}

func newRustReader(b *bucket, key string, o *xlObject) *rustReader {
	r := &rustReader{b: b, dir: key, ddir: o.ddir, size: o.size, bs: o.blockSize, inline: o.inline}
	var start int64
	for i, n := range o.partNums {
		r.parts = append(r.parts, rustPart{num: n, size: o.partSizes[i], start: start})
		start += o.partSizes[i]
	}
	return r
}

func (r *rustReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}

// readFramed reads from the framed stream (part file or inline bytes) at a file offset.
func (r *rustReader) readFramed(p rustPart, fileOff int64, buf []byte) error {
	if r.inline != nil {
		_, err := bytes.NewReader(r.inline).ReadAt(buf, fileOff)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil || r.curNum != p.num {
		if r.cur != nil {
			r.cur.Close()
			r.cur = nil
		}
		name := filepath.FromSlash(r.dir + "/" + r.ddir + "/part." + strconv.FormatInt(p.num, 10))
		f, err := r.b.root.Open(name)
		if err != nil {
			return err
		}
		r.cur, r.curNum = f, p.num
	}
	_, err := r.cur.ReadAt(buf, fileOff)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (r *rustReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	n := 0
	for n < len(p) && off < r.size {
		pi := sort.Search(len(r.parts), func(i int) bool { return r.parts[i].start+r.parts[i].size > off })
		if pi >= len(r.parts) {
			break
		}
		pt := r.parts[pi]
		po := off - pt.start
		blk, in := po/r.bs, po%r.bs
		blkLen := r.bs
		if rest := pt.size - blk*r.bs; rest < blkLen {
			blkLen = rest
		}
		want := int64(len(p) - n)
		if blkLen-in < want {
			want = blkLen - in
		}
		fileOff := blk*(bitrotHashLen+r.bs) + bitrotHashLen + in
		if err := r.readFramed(pt, fileOff, p[n:n+int(want)]); err != nil {
			return n, err
		}
		n += int(want)
		off += want
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ---------------------------------------------------------------- folder tree of a RustFS data folder

var rustHidden = map[string]bool{".rustfs.sys": true, ".minio.sys": true}

func joinKey(parts []string) string { return strings.Join(parts, "/") }

// depthOf is the number of components of a directory key ("" = 0, "a/b/" = 2).
func depthOf(dirKey string) int {
	if dirKey == "" {
		return 0
	}
	return strings.Count(strings.TrimSuffix(dirKey, "/"), "/") + 1
}

func (b *bucket) isXLDir(key string) bool {
	st, err := b.root.Lstat(relPath(key + "/xl.meta"))
	return err == nil && st.Mode().IsRegular()
}

// insideObject: some component below the RustFS bucket level is an object folder (so the path points into its internals).
func (b *bucket) insideObject(parts []string) bool {
	for i := b.bucketIdx + 2; i <= len(parts); i++ {
		if b.isXLDir(joinKey(parts[:i])) {
			return true
		}
	}
	return false
}

func (b *bucket) loadXL(key string) (*xlObject, error) {
	f, err := b.root.Open(relPath(key + "/xl.meta"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxXLMeta {
		return nil, fs.ErrNotExist
	}
	data, err := io.ReadAll(io.LimitReader(f, maxXLMeta))
	if err != nil {
		return nil, err
	}
	return parseXL(data)
}

// readDirRust lists a folder of the RustFS tree: sub folders are prefixes, folders holding an xl.meta are objects.
func (b *bucket) readDirRust(dirKey string) []child {
	depth := depthOf(dirKey)
	if dirKey != "" && b.insideObject(strings.Split(strings.TrimSuffix(dirKey, "/"), "/")) {
		return nil
	}
	rel := "."
	if dirKey != "" {
		rel = relPath(strings.TrimSuffix(dirKey, "/"))
	}
	f, err := b.root.Open(rel)
	if err != nil {
		return nil
	}
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil && len(des) == 0 {
		return nil
	}
	out := make([]child, 0, len(des))
	for _, de := range des {
		n := de.Name()
		if !validName(n) || (dirKey == "" && n == ".zfs") || !de.Type().IsDir() {
			continue // objects are folders: loose files are no objects
		}
		if depth == b.bucketIdx && rustHidden[n] {
			continue
		}
		if depth >= b.bucketIdx+1 {
			key := dirKey + n
			if b.isXLDir(key) {
				k := key
				out = append(out, child{name: n, stat: func() fileMeta {
					o, err := b.loadXL(k)
					if err != nil {
						return fileMeta{}
					}
					return fileMeta{size: o.size, mtime: o.mtime, etag: o.etag, ok: true}
				}})
				continue
			}
		}
		out = append(out, child{name: n, isDir: true})
	}
	return out
}

// openRust opens the data of an object.
func (b *bucket) openRust(key string) (*object, error) {
	if !validKey(key) || b.topHidden(key) {
		return nil, fs.ErrNotExist
	}
	parts := strings.Split(key, "/")
	if len(parts) < b.bucketIdx+2 || rustHidden[parts[b.bucketIdx]] || b.insideObject(parts[:len(parts)-1]) {
		return nil, fs.ErrNotExist
	}
	o, err := b.loadXL(key)
	if err != nil {
		if errors.Is(err, errDeleteMarker) {
			return nil, fs.ErrNotExist
		}
		var u *errUnsupported
		if errors.As(err, &u) {
			return nil, err
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil, err
		}
		return nil, &errUnsupported{"cannot read the RustFS object: " + err.Error()}
	}
	if o.unsupp != "" {
		return nil, &errUnsupported{o.unsupp}
	}
	rr := newRustReader(b, key, o)
	return &object{r: io.NewSectionReader(rr, 0, o.size), close: rr.Close, size: o.size, mtime: o.mtime, etag: o.etag, ctype: o.ctype}, nil
}
