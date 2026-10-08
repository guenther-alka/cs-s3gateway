package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowse(t *testing.T) {
	dir := makeTree(t)
	os.WriteFile(filepath.Join(dir, "a&b.txt"), []byte("amp"), 0o644)
	os.WriteFile(filepath.Join(dir, "p.html"), []byte("<script>alert(1)</script>"), 0o644)
	ts := httptest.NewServer(newTestGateway(t, dir))
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(path, user, pass string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	if r, _ := get("/_browse/", "", ""); r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no auth: want 401+challenge, got %d", r.StatusCode)
	}
	if r, _ := get("/_browse/", tAccess, "wrong"); r.StatusCode != 401 {
		t.Fatalf("bad pw: got %d", r.StatusCode)
	}
	r, body := get("/_browse/", tAccess, tSecret)
	if r.StatusCode != 200 || !strings.Contains(body, "bk") {
		t.Fatalf("bucket list: %d %q", r.StatusCode, body)
	}
	if r.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("CSP missing")
	}
	r, body = get("/_browse/bk/", tAccess, tSecret)
	if r.StatusCode != 200 || !strings.Contains(body, "a.txt") {
		t.Fatalf("dir list: %d", r.StatusCode)
	}
	if strings.Contains(body, ">a&b.txt<") || !strings.Contains(body, ">a&amp;b.txt<") {
		t.Fatalf("html not escaped: %s", body)
	}
	if strings.Contains(body, ".zfs") {
		t.Fatal(".zfs visible")
	}
	r, body = get("/_browse/bk/a.txt", tAccess, tSecret)
	if r.StatusCode != 200 || body != "hello world" {
		t.Fatalf("download: %d %q", r.StatusCode, body)
	}
	if _, lb := get("/_browse/bk/", tAccess, tSecret); !strings.Contains(lb, "a.txt?dl=1") {
		t.Fatal("download link missing")
	}
	r, _ = get("/_browse/bk/a.txt", tAccess, tSecret)
	if r.Header.Get("Content-Disposition") != "" {
		t.Fatalf("txt should be inline, got %q", r.Header.Get("Content-Disposition"))
	}
	r, _ = get("/_browse/bk/a.txt?dl=1", tAccess, tSecret)
	if !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("dl=1 must be attachment, got %q", r.Header.Get("Content-Disposition"))
	}
	r, _ = get("/_browse/bk/p.html", tAccess, tSecret)
	if !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("html must be attachment, got %q", r.Header.Get("Content-Disposition"))
	}
	for _, p := range []string{"/_browse/bk/.zfs/hidden.txt", "/_browse/bk/../x", "/_browse/bk/%2e%2e/x", "/_browse/nope/"} {
		if r, _ := get(p, tAccess, tSecret); r.StatusCode == 200 {
			t.Fatalf("%s must not be 200", p)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/_browse/bk/", strings.NewReader("x"))
	req.SetBasicAuth(tAccess, tSecret)
	resp, _ := client.Do(req)
	if resp.StatusCode != 405 {
		t.Fatalf("POST: got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
