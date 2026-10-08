package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

type apiErr struct {
	status int
	code   string
	msg    string
}

type gateway struct {
	buckets map[string]*bucket
	names   []string
	access  string
	secret  string
	maxKeys int
	logger  *log.Logger
	started time.Time
	now     func() time.Time
	lim     *limiter
	active  atomic.Int64
	lastUse atomic.Int64 // unix nano of the last finished request
}

// ---------------------------------------------------------------- failed-auth limiter

type limiter struct {
	mu sync.Mutex
	m  map[string]*failState
}

type failState struct {
	n       int
	first   time.Time
	blocked time.Time
}

func newLimiter() *limiter { return &limiter{m: map[string]*failState{}} }

// limitKey maps a client address to the limiter key: IPv6 clients are grouped by /64
// (one subscriber owns a whole /64 and could otherwise rotate addresses to dodge the limit).
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

func (l *limiter) isBlocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[limitKey(ip)]
	return f != nil && now.Before(f.blocked)
}

// fail counts a failed authentication; 10 failures within a minute block the address for a minute.
func (l *limiter) fail(ip string, now time.Time) {
	ip = limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 4096 { // keep it bounded: drop expired entries, never active blocks
		for k, f := range l.m {
			if now.Sub(f.first) > time.Minute && !now.Before(f.blocked) {
				delete(l.m, k)
			}
		}
		if len(l.m) > 8192 { // flood of distinct sources: forget the oldest-looking half only as a last resort
			for k, f := range l.m {
				if !now.Before(f.blocked) {
					delete(l.m, k)
				}
			}
		}
	}
	f := l.m[ip]
	if f == nil || now.Sub(f.first) > time.Minute {
		f = &failState{first: now}
		l.m[ip] = f
	}
	f.n++
	if f.n >= 10 {
		f.blocked = now.Add(time.Minute)
	}
}

// ---------------------------------------------------------------- response helpers

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(c int) {
	if s.status == 0 {
		s.status = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = 200
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func reqID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func writeErr(w http.ResponseWriter, r *http.Request, e *apiErr) {
	w.Header().Set("Content-Type", "application/xml")
	if r.Method == http.MethodHead {
		w.WriteHeader(e.status)
		return
	}
	type s3Error struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string
		Message   string
		Resource  string
		RequestId string
	}
	w.WriteHeader(e.status)
	b, _ := xml.Marshal(s3Error{Code: e.code, Message: e.msg, Resource: r.URL.Path, RequestId: w.Header().Get("x-amz-request-id")})
	w.Write([]byte(xml.Header))
	w.Write(b)
}

func writeXML(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(200)
	b, _ := xml.Marshal(v)
	w.Write([]byte(xml.Header))
	w.Write(b)
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------- request entry

func (g *gateway) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	g.active.Add(1)
	defer func() {
		g.active.Add(-1)
		g.lastUse.Store(time.Now().UnixNano())
	}()
	w := &statusWriter{ResponseWriter: rw}
	start := time.Now()
	ip := remoteIP(r)
	rw.Header().Set("Server", "cs-s3gateway")
	rw.Header().Set("x-amz-request-id", reqID())
	authOK := false
	defer func() {
		g.logger.Printf("%s %s %q %d %dB %s auth=%v", ip, r.Method, r.URL.Path, w.status, w.bytes, time.Since(start).Round(time.Millisecond), authOK)
	}()

	if g.lim.isBlocked(ip, g.now()) {
		writeErr(w, r, &apiErr{429, "SlowDown", "too many failed requests, try again later"})
		return
	}
	if isBrowseRequest(r) {
		authOK = g.browse(w, r, ip)
		return
	}
	if e := g.authenticate(r); e != nil {
		g.lim.fail(ip, g.now())
		writeErr(w, r, e)
		return
	}
	authOK = true
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		rw.Header().Set("Connection", "close")
		writeErr(w, r, errDenied("cs-s3gateway is read-only"))
		return
	}

	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		g.listBuckets(w, r)
		return
	}
	name, key := p, ""
	if i := strings.IndexByte(p, '/'); i >= 0 {
		name, key = p[:i], p[i+1:]
	}
	b := g.buckets[name]
	if b == nil {
		writeErr(w, r, &apiErr{404, "NoSuchBucket", "The specified bucket does not exist"})
		return
	}
	if key == "" {
		g.bucketOp(w, r, b)
		return
	}
	g.getObject(w, r, b, key)
}

func (g *gateway) listBuckets(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.WriteHeader(200)
		return
	}
	type bk struct {
		Name         string
		CreationDate string
	}
	type res struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Xmlns   string   `xml:"xmlns,attr"`
		Owner   struct{ ID, DisplayName string }
		Buckets struct {
			Bucket []bk
		}
	}
	var v res
	v.Xmlns = xmlns
	v.Owner.ID, v.Owner.DisplayName = "cs-s3gateway", "cs-s3gateway"
	for _, n := range g.names {
		v.Buckets.Bucket = append(v.Buckets.Bucket, bk{n, g.started.UTC().Format("2006-01-02T15:04:05.000Z")})
	}
	writeXML(w, v)
}

// listParams are the only query parameters a bucket GET accepts besides X-Amz-* ones.
var listParams = map[string]bool{"list-type": true, "prefix": true, "delimiter": true, "max-keys": true,
	"continuation-token": true, "start-after": true, "marker": true, "encoding-type": true, "fetch-owner": true}

func (g *gateway) bucketOp(w http.ResponseWriter, r *http.Request, b *bucket) {
	w.Header().Set("x-amz-bucket-region", "us-east-1")
	if r.Method == http.MethodHead {
		w.WriteHeader(200)
		return
	}
	q := r.URL.Query()
	if _, ok := q["location"]; ok {
		writeXML(w, struct {
			XMLName xml.Name `xml:"LocationConstraint"`
			Xmlns   string   `xml:"xmlns,attr"`
		}{Xmlns: xmlns})
		return
	}
	if _, ok := q["versioning"]; ok {
		writeXML(w, struct {
			XMLName xml.Name `xml:"VersioningConfiguration"`
			Xmlns   string   `xml:"xmlns,attr"`
		}{Xmlns: xmlns})
		return
	}
	for k := range q {
		if !listParams[k] && !strings.HasPrefix(k, "X-Amz-") {
			writeErr(w, r, &apiErr{501, "NotImplemented", "this bucket operation is not supported (read-only gateway)"})
			return
		}
	}
	g.handleList(w, r, b)
}

type content struct {
	Key          string
	LastModified string
	ETag         string
	Size         int64
	StorageClass string
}

type commonPrefix struct{ Prefix string }

func (g *gateway) handleList(w http.ResponseWriter, r *http.Request, b *bucket) {
	q := r.URL.Query()
	bad := func(m string) { writeErr(w, r, &apiErr{400, "InvalidArgument", m}) }
	lt := q.Get("list-type")
	if lt != "" && lt != "2" {
		bad("list-type must be 2")
		return
	}
	v2 := lt == "2"
	max := g.maxKeys
	if s := q.Get("max-keys"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			bad("max-keys must be a non-negative integer")
			return
		}
		if n < max {
			max = n
		}
	}
	enc := q.Get("encoding-type")
	if enc != "" && enc != "url" {
		bad("encoding-type must be url")
		return
	}
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	var marker, token string
	if v2 {
		if token = q.Get("continuation-token"); token != "" {
			d, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				bad("invalid continuation-token")
				return
			}
			marker = string(d)
		} else {
			marker = q.Get("start-after")
		}
	} else {
		marker = q.Get("marker")
	}

	items, truncated := b.list(prefix, delim, marker, max)
	esc := func(s string) string {
		if enc == "url" {
			return awsEncode(s, false)
		}
		return s
	}
	var contents []content
	var prefixes []commonPrefix
	for _, e := range items {
		if e.isPrefix {
			prefixes = append(prefixes, commonPrefix{esc(e.key)})
			continue
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", e.size, e.mtime.UnixNano())))
		contents = append(contents, content{esc(e.key), e.mtime.UTC().Format("2006-01-02T15:04:05.000Z"),
			`"` + hex.EncodeToString(sum[:16]) + `"`, e.size, "STANDARD"})
	}
	last := ""
	if len(items) > 0 {
		last = items[len(items)-1].key
	}

	type common struct {
		XMLName        xml.Name `xml:"ListBucketResult"`
		Xmlns          string   `xml:"xmlns,attr"`
		Name           string
		Prefix         string
		KeyCount       *int     `xml:",omitempty"`
		MaxKeys        int
		Delimiter      string   `xml:",omitempty"`
		EncodingType   string   `xml:",omitempty"`
		IsTruncated    bool
		ContinuationTk string   `xml:"ContinuationToken,omitempty"`
		NextContinuTk  string   `xml:"NextContinuationToken,omitempty"`
		StartAfter     string   `xml:"StartAfter,omitempty"`
		Marker         *string  `xml:"Marker,omitempty"`
		NextMarker     string   `xml:"NextMarker,omitempty"`
		Contents       []content
		CommonPrefixes []commonPrefix
	}
	v := common{Xmlns: xmlns, Name: b.name, Prefix: esc(prefix), MaxKeys: max, Delimiter: delim, EncodingType: enc,
		IsTruncated: truncated, Contents: contents, CommonPrefixes: prefixes}
	if v2 {
		n := len(contents) + len(prefixes)
		v.KeyCount = &n
		v.ContinuationTk = token
		if token == "" {
			v.StartAfter = esc(marker)
		}
		if truncated {
			v.NextContinuTk = base64.RawURLEncoding.EncodeToString([]byte(last))
		}
	} else {
		m := esc(marker)
		v.Marker = &m
		if truncated {
			v.NextMarker = esc(last)
		}
	}
	writeXML(w, v)
}

func (g *gateway) getObject(w http.ResponseWriter, r *http.Request, b *bucket, key string) {
	nokey := &apiErr{404, "NoSuchKey", "The specified key does not exist."}
	f, st, err := b.openRegular(key)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			writeErr(w, r, errDenied("Access Denied"))
		} else {
			writeErr(w, r, nokey)
		}
		return
	}
	defer f.Close()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", st.Size(), st.ModTime().UnixNano())))
	h := w.Header()
	h.Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	ct := mime.TypeByExtension(strings.ToLower(path.Ext(key)))
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	// a presigned URL opened in a browser must never run a file as a page of the gateway origin
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	base := ct
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = base[:i]
	}
	if !inlineTypes[base] {
		h.Set("Content-Disposition", "attachment")
	}
	h.Set("x-amz-storage-class", "STANDARD")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

func sortedNames(m map[string]*bucket) []string {
	n := make([]string, 0, len(m))
	for k := range m {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}
