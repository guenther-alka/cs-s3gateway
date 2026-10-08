package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Real RustFS data generated with rustfs.exe (single disk). Set CS_RUSTFS_TESTDATA to the "vol1" folder.
func rustTestData(t *testing.T) string {
	d := os.Getenv("CS_RUSTFS_TESTDATA")
	if d == "" {
		d = `C:\opt\tmp\rfs_testdata\vol1`
	}
	if !isDir(filepath.Join(d, "testbucket")) {
		t.Skip("no RustFS test data")
	}
	return d
}

func openTestBucket(t *testing.T, dir string, kind, idx int) *bucket {
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &bucket{name: "t", path: dir, root: root, kind: kind, bucketIdx: idx}
}

func readAll(t *testing.T, b *bucket, key string) []byte {
	o, err := b.openObject(key)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	defer o.close()
	data, err := io.ReadAll(o.r)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	if int64(len(data)) != o.size {
		t.Fatalf("%s: size %d != %d", key, len(data), o.size)
	}
	return data
}

func TestRustFSRead(t *testing.T) {
	dir := rustTestData(t)
	b := openTestBucket(t, dir, kindRust, 0)

	items, _ := b.list("testbucket/", "/", "", 100)
	names := map[string]bool{}
	for _, e := range items {
		names[e.key] = true
	}
	for _, k := range []string{"testbucket/tiny.txt", "testbucket/mid.bin", "testbucket/big.bin", "testbucket/multi.bin", "testbucket/dir/"} {
		if !names[k] {
			t.Errorf("missing %q in %v", k, names)
		}
	}
	if names["testbucket/tiny.txt/"] || names["testbucket/big.bin/"] {
		t.Error("object folders must not show as prefixes")
	}
	if got := string(readAll(t, b, "testbucket/dir/sub/nested.txt")); got == "" {
		t.Error("nested empty")
	}
	big := readAll(t, b, "testbucket/big.bin")
	sum := sha256.Sum256(big)
	if hex.EncodeToString(sum[:]) != "ec854dd9d22d5a701c79bb00cd5b07e389dcb4ac20e111005f57d3135d172e97" {
		t.Error("big.bin content differs")
	}
	if len(readAll(t, b, "testbucket/multi.bin")) != 3*5<<20 {
		t.Error("multi.bin size")
	}
	// internals are not addressable
	for _, k := range []string{"testbucket/big.bin/xl.meta", "testbucket/tiny.txt/xl.meta", ".rustfs.sys/x", "testbucket/dir"} {
		if _, err := b.openObject(k); err == nil {
			t.Errorf("%q must not open", k)
		}
	}
	// recursive listing sees the nested object, no internals
	all, _ := b.list("testbucket/", "", "", 100)
	for _, e := range all {
		if filepath.Base(e.key) == "xl.meta" || filepath.Base(e.key) == "part.1" {
			t.Errorf("internal file listed: %s", e.key)
		}
	}
}

func TestRustFSVersions(t *testing.T) {
	dir := rustTestData(t)
	vd := filepath.Join(dir, "verbucket")
	if !isDir(vd) {
		t.Skip("no verbucket")
	}
	b := openTestBucket(t, dir, kindRust, 0)
	if got := string(readAll(t, b, "verbucket/v.txt")); got != "version two\n" {
		t.Errorf("latest version expected, got %q", got)
	}
	if _, err := b.openObject("verbucket/gone.txt"); err == nil || errors.As(err, new(*errUnsupported)) {
		t.Errorf("delete marker must read as not found, got %v", err)
	}
	items, _ := b.list("verbucket/", "/", "", 100)
	for _, e := range items {
		if e.key == "verbucket/gone.txt" {
			t.Error("deleted object listed")
		}
	}
}

func TestRustFSSnapLayout(t *testing.T) {
	dir := rustTestData(t)
	snaps := filepath.Join(t.TempDir(), "snaps")
	if err := os.CopyFS(filepath.Join(snaps, "snap1"), os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	b := openTestBucket(t, snaps, kindRustSnap, 1)
	items, _ := b.list("", "/", "", 100)
	if len(items) != 1 || items[0].key != "snap1/" {
		t.Fatalf("snapshots: %v", items)
	}
	items, _ = b.list("snap1/testbucket/", "/", "", 100)
	if len(items) < 5 {
		t.Fatalf("objects in snapshot: %v", items)
	}
	if string(readAll(t, b, "snap1/testbucket/tiny.txt")) == "" {
		t.Error("tiny.txt empty")
	}
}
