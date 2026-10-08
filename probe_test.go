package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// regression tests for the security audit findings

// .zfs must stay hidden under every spelling the file system treats as the same folder.
func TestZfsHiddenAliases(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".zfs"), 0o755)
	os.WriteFile(filepath.Join(dir, ".zfs", "hidden.txt"), []byte("H"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("A"), 0o644)
	ts := httptest.NewServer(newTestGateway(t, dir))
	defer ts.Close()
	get := func(k string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/_browse/bk/"+k, nil)
		req.SetBasicAuth(tAccess, tSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("a.txt") != 200 {
		t.Fatal("a.txt must be readable")
	}
	dirs := []string{".zfs"}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		dirs = append(dirs, ".ZFS", ".zfs.", "ZFS~1")
	}
	for _, d := range dirs {
		if c := get(d + "/hidden.txt"); c == 200 {
			t.Errorf("%q/hidden.txt reaches the hidden .zfs folder", d)
		}
		if c := get(d + "/"); c == 200 {
			t.Errorf("listing %q/ reaches the hidden .zfs folder", d)
		}
	}
}

// an unauthenticated first request (login challenge) is not a failed login, wrong credentials are
func TestBrowseLimiterCounting(t *testing.T) {
	g := newTestGateway(t, t.TempDir())
	ts := httptest.NewServer(g)
	defer ts.Close()
	for i := 0; i < 15; i++ {
		resp, _ := http.Get(ts.URL + "/_browse/")
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("challenge %d: got %d", i, resp.StatusCode)
		}
	}
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/_browse/", nil)
		req.SetBasicAuth(tAccess, "wrong")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}
	req, _ := http.NewRequest("GET", ts.URL+"/_browse/", nil)
	req.SetBasicAuth(tAccess, tSecret)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("after 10 wrong passwords: want 429, got %d", resp.StatusCode)
	}
}

func TestLimiterIPv6Group(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 10; i++ { // ten different addresses of one /64
		l.fail(fmt.Sprintf("2001:db8:1:2::%x", i+1), now)
	}
	if !l.isBlocked("2001:db8:1:2::ffff", now) {
		t.Fatal("addresses of one /64 must share the limit")
	}
	if l.isBlocked("2001:db8:1:3::1", now) {
		t.Fatal("another /64 must not be blocked")
	}
	if limitKey("::ffff:192.0.2.1") != "192.0.2.1" {
		t.Fatal("mapped IPv4 address")
	}
}

// buckets must never make server.auth / _cfg / the TLS key readable, not even through snapshots
func TestExposes(t *testing.T) {
	base := t.TempDir()
	cfg := filepath.Join(base, "csweb-gui", "_cfg")
	os.MkdirAll(cfg, 0o755)
	os.MkdirAll(filepath.Join(base, "csweb-gui", "data"), 0o755)
	prot := []string{cfg}
	if exposes(base, prot) == "" {
		t.Fatal("parent of _cfg must be refused")
	}
	if exposes(filepath.Join(base, "csweb-gui"), prot) == "" {
		t.Fatal("napp-it folder must be refused")
	}
	if exposes(cfg, prot) == "" {
		t.Fatal("_cfg itself must be refused")
	}
	if exposes(t.TempDir(), prot) != "" {
		t.Fatal("unrelated folder must be fine")
	}
	if exposes(filepath.Join(base, "csweb-gui", "data"), prot) != "" {
		t.Fatal("sibling folder must be fine")
	}
}

// the S3 GET must not let a browser run a stored page on the gateway origin
func TestS3GetHeaders(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.html"), []byte("<script>1</script>"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("A"), 0o644)
	ts := httptest.NewServer(newTestGateway(t, dir))
	defer ts.Close()
	for k, wantAtt := range map[string]bool{"p.html": true, "a.txt": false} {
		req, _ := http.NewRequest("GET", ts.URL+"/bk/"+k, nil)
		signReq(req, tAccess, tSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != "sandbox" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: status %d, CSP %q", k, resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
		}
		if got := resp.Header.Get("Content-Disposition") != ""; got != wantAtt {
			t.Fatalf("%s: attachment=%v want %v", k, got, wantAtt)
		}
	}
}
