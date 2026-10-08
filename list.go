package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// bucket is one exported folder. All file access goes through os.Root, so a key can never
// leave the folder (no "..", no symlink escaping the root).
type bucket struct {
	name string
	path string
	root *os.Root
}

type entry struct {
	key      string // object key, or common prefix ending in the delimiter
	isPrefix bool
	size     int64
	mtime    time.Time
}

// validName: names that cannot be addressed or XML-encoded safely are invisible.
func validName(n string) bool {
	if n == "" || n == "." || n == ".." || !utf8.ValidString(n) {
		return false
	}
	for _, c := range n {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

// validKey: every component must be a valid name, ".zfs" at the top level is hidden.
func validKey(key string) bool {
	if key == "" || strings.HasSuffix(key, "/") {
		return false
	}
	parts := strings.Split(key, "/")
	for i, p := range parts {
		if !validName(p) || (i == 0 && p == ".zfs") {
			return false
		}
	}
	return true
}

func relPath(key string) string { return filepath.FromSlash(key) }

// topHidden reports whether the first component of a key or prefix is the hidden top level ".zfs" -
// by name or, on case-insensitive / aliasing file systems (Windows, macOS: ".ZFS", ".zfs.", "ZFS~1"),
// because it is the very same folder.
func (b *bucket) topHidden(keyOrPrefix string) bool {
	first := keyOrPrefix
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if first == ".zfs" {
		return true
	}
	if first == "" {
		return false
	}
	zi, err := b.root.Lstat(".zfs")
	if err != nil {
		return false
	}
	ti, err := b.root.Lstat(relPath(first))
	return err == nil && os.SameFile(zi, ti)
}

// openRegular opens a key for reading: only regular files (Lstat first: no symlink, and opening a
// fifo or device would block), always through os.Root.
func (b *bucket) openRegular(key string) (*os.File, fs.FileInfo, error) {
	if !validKey(key) || b.topHidden(key) {
		return nil, nil, fs.ErrNotExist
	}
	lst, err := b.root.Lstat(relPath(key))
	if err != nil {
		return nil, nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, nil, fs.ErrNotExist
	}
	f, err := b.root.Open(relPath(key))
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, fs.ErrNotExist
	}
	return f, st, nil
}

type child struct {
	name  string
	isDir bool
	de    fs.DirEntry
}

// readDir lists the valid children (regular files and directories only, no symlinks).
func (b *bucket) readDir(dirKey string) []child {
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
		if !validName(n) || (dirKey == "" && n == ".zfs") {
			continue
		}
		t := de.Type()
		switch {
		case t.IsDir():
			out = append(out, child{n, true, de})
		case t.IsRegular():
			out = append(out, child{n, false, de})
		}
	}
	return out
}

func fileEntry(key string, de fs.DirEntry) (entry, bool) {
	info, err := de.Info()
	if err != nil || !info.Mode().IsRegular() {
		return entry{}, false
	}
	return entry{key: key, size: info.Size(), mtime: info.ModTime()}, true
}

// list returns up to max entries (keys and common prefixes) in key order, all > marker.
func (b *bucket) list(prefix, delim, marker string, max int) (items []entry, truncated bool) {
	if max <= 0 {
		return nil, false
	}
	if delim == "/" {
		return b.listOneLevel(prefix, marker, max)
	}
	return b.listRecursive(prefix, delim, marker, max)
}

// listOneLevel handles the usual delimiter "/": a single directory is read.
func (b *bucket) listOneLevel(prefix, marker string, max int) ([]entry, bool) {
	dir, namePrefix := "", prefix
	if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
		dir, namePrefix = prefix[:i+1], prefix[i+1:]
	}
	if dir != "" {
		for _, p := range strings.Split(strings.TrimSuffix(dir, "/"), "/") {
			if !validName(p) {
				return nil, false
			}
		}
		if b.topHidden(dir) {
			return nil, false
		}
	}
	type cand struct {
		emit string
		c    child
	}
	var cands []cand
	for _, c := range b.readDir(dir) {
		if !strings.HasPrefix(c.name, namePrefix) {
			continue
		}
		emit := dir + c.name
		if c.isDir {
			emit += "/"
		}
		if emit <= marker {
			continue
		}
		cands = append(cands, cand{emit, c})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].emit < cands[j].emit })
	var out []entry
	for _, cd := range cands {
		var e entry
		if cd.c.isDir {
			e = entry{key: cd.emit, isPrefix: true}
		} else {
			var ok bool
			if e, ok = fileEntry(cd.emit, cd.c.de); !ok {
				continue
			}
		}
		if len(out) == max {
			return out, true
		}
		out = append(out, e)
	}
	return out, false
}

type walker struct {
	b         *bucket
	prefix    string
	delim     string
	marker    string
	max       int
	out       []entry
	truncated bool
	lastCP    string
}

// listRecursive walks the tree in key order (dirs sort as name+"/"), optional generic delimiter.
func (b *bucket) listRecursive(prefix, delim, marker string, max int) ([]entry, bool) {
	w := &walker{b: b, prefix: prefix, delim: delim, marker: marker, max: max}
	w.walk("")
	return w.out, w.truncated
}

func (w *walker) add(e entry) bool {
	if len(w.out) == w.max {
		w.truncated = true
		return false
	}
	w.out = append(w.out, e)
	return true
}

func (w *walker) walk(dirKey string) bool {
	cs := w.b.readDir(dirKey)
	sortKey := func(c child) string {
		if c.isDir {
			return c.name + "/"
		}
		return c.name
	}
	sort.Slice(cs, func(i, j int) bool { return sortKey(cs[i]) < sortKey(cs[j]) })
	for _, c := range cs {
		if c.isDir {
			dp := dirKey + c.name + "/"
			if !strings.HasPrefix(dp, w.prefix) && !strings.HasPrefix(w.prefix, dp) {
				continue
			}
			if w.marker != "" && dp < w.marker && !strings.HasPrefix(w.marker, dp) {
				continue
			}
			if !w.walk(dp) {
				return false
			}
			continue
		}
		key := dirKey + c.name
		if !strings.HasPrefix(key, w.prefix) || key <= w.marker {
			continue
		}
		if w.delim != "" {
			rest := key[len(w.prefix):]
			if i := strings.Index(rest, w.delim); i >= 0 {
				cp := w.prefix + rest[:i+len(w.delim)]
				if cp == w.lastCP || cp <= w.marker {
					continue
				}
				w.lastCP = cp
				if !w.add(entry{key: cp, isPrefix: true}) {
					return false
				}
				continue
			}
		}
		e, ok := fileEntry(key, c.de)
		if !ok {
			continue
		}
		if !w.add(e) {
			return false
		}
	}
	return true
}
