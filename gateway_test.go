package main

import (
	"encoding/hex"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	tAccess = "s3admin"
	tSecret = "0123456789abcdefghij"
)

func newTestGateway(t *testing.T, dir string) *gateway {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	g := &gateway{buckets: map[string]*bucket{"bk": {name: "bk", path: dir, root: root}}, access: tAccess, secret: tSecret,
		maxKeys: 1000, logger: log.New(io.Discard, "", 0), started: time.Now(), now: time.Now, lim: newLimiter()}
	g.names = sortedNames(g.buckets)
	return g
}

// signReq signs r like an S3 client (header based SigV4, unsigned empty body).
func signReq(r *http.Request, access, secret string) {
	amz := time.Now().UTC().Format("20060102T150405Z")
	date := amz[:8]
	r.Header.Set("X-Amz-Date", amz)
	r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	scope := date + "/us-east-1/s3/aws4_request"
	canon := canonicalRequest(r, signed, emptySHA256, false)
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, date, "us-east-1", "s3"), stringToSign(amz, scope, canon)))
	r.Header.Set("Authorization", algo+" Credential="+access+"/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+sig)
}

func TestAWSVectors(t *testing.T) {
	g := &gateway{access: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}

	// documented "GET Object" example (Authenticating Requests: Using the Authorization Header)
	r, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"+
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"+
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
	if e := g.authenticate(r); e != nil {
		t.Fatalf("header example rejected: %+v", e)
	}

	// documented presigned URL example
	u := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	r2, _ := http.NewRequest("GET", u, nil)
	if e := g.authenticate(r2); e != nil {
		t.Fatalf("presigned example rejected: %+v", e)
	}
	// expired
	g.now = func() time.Time { return time.Date(2013, 5, 26, 0, 0, 0, 0, time.UTC) }
	if e := g.authenticate(r2); e == nil {
		t.Fatal("expired presigned URL accepted")
	}
}

type listOut struct {
	Contents       []struct{ Key string }
	CommonPrefixes []struct{ Prefix string }
	IsTruncated    bool
	NextToken      string `xml:"NextContinuationToken"`
}

func makeTree(t *testing.T) string {
	dir := t.TempDir()
	files := map[string]string{
		"a.txt": "hello world", "ä.txt": "umlaut", "a b.txt": "space",
		"dir/b.txt": "bbb", "dir/sub/c.txt": "ccc", "dir/sub.txt": "sss", "dir2/x y.txt": "xy",
		".zfs/hidden.txt": "secret", "bad\\name.txt": "backslash",
	}
	for k, v := range files {
		if runtime.GOOS == "windows" && strings.Contains(k, `\`) {
			continue // a backslash is a path separator there
		}
		p := filepath.Join(dir, filepath.FromSlash(k))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil && !strings.Contains(k, `\`) {
			t.Fatal(err)
		}
	}
	return dir
}

func TestEndToEnd(t *testing.T) {
	dir := makeTree(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("outside"), 0o644)
	if os.Symlink(outside, filepath.Join(dir, "link.txt")) != nil {
		t.Log("symlinks not available, skipping symlink check")
	}
	ts := httptest.NewServer(newTestGateway(t, dir))
	defer ts.Close()

	do := func(method, p string, signed bool) (int, string, http.Header) {
		r, _ := http.NewRequest(method, ts.URL+p, nil)
		if signed {
			signReq(r, tAccess, tSecret)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	list := func(q string) listOut {
		c, body, _ := do("GET", "/bk?list-type=2"+q, true)
		if c != 200 {
			t.Fatalf("list %q: %d %s", q, c, body)
		}
		var lo listOut
		if err := xml.Unmarshal([]byte(body), &lo); err != nil {
			t.Fatal(err)
		}
		return lo
	}
	keys := func(lo listOut) []string {
		var k []string
		for _, c := range lo.Contents {
			k = append(k, c.Key)
		}
		for _, c := range lo.CommonPrefixes {
			k = append(k, c.Prefix)
		}
		sort.Strings(k) // S3 lists Contents and CommonPrefixes separately: compare as one merged sequence
		return k
	}

	if c, body, _ := do("GET", "/bk/a.txt", false); c != 403 || !strings.Contains(body, "AccessDenied") {
		t.Errorf("unsigned: %d %s", c, body)
	}
	r, _ := http.NewRequest("GET", ts.URL+"/bk/a.txt", nil)
	signReq(r, tAccess, "wrongwrongwrongwrong")
	if resp, _ := http.DefaultClient.Do(r); resp.StatusCode != 403 {
		t.Errorf("wrong secret: %d", resp.StatusCode)
	}
	if c, body, _ := do("GET", "/", true); c != 200 || !strings.Contains(body, "<Name>bk</Name>") {
		t.Errorf("list buckets: %d %s", c, body)
	}
	if c, body, _ := do("GET", "/nobucket/x", true); c != 404 || !strings.Contains(body, "NoSuchBucket") {
		t.Errorf("no bucket: %d %s", c, body)
	}

	// one level
	got := keys(list("&delimiter=%2F"))
	want := []string{"a b.txt", "a.txt", "dir/", "dir2/", "ä.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("one level: %v want %v", got, want)
	}
	got = keys(list("&delimiter=%2F&prefix=dir%2F"))
	want = []string{"dir/b.txt", "dir/sub.txt", "dir/sub/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dir/: %v want %v", got, want)
	}
	// recursive: complete, sorted, no .zfs, no backslash name, no symlink
	all := keys(list(""))
	want = []string{"a b.txt", "a.txt", "dir/b.txt", "dir/sub.txt", "dir/sub/c.txt", "dir2/x y.txt", "ä.txt"}
	if !sort.StringsAreSorted(all) || !reflect.DeepEqual(all, want) {
		t.Errorf("recursive: %v want %v", all, want)
	}
	// paging with one key per page must give the same sequence
	for _, d := range []string{"", "&delimiter=%2F", "&delimiter=sub"} {
		full := keys(list(d))
		var paged []string
		tok := ""
		for i := 0; i < 50; i++ {
			q := d + "&max-keys=1"
			if tok != "" {
				q += "&continuation-token=" + url.QueryEscape(tok)
			}
			lo := list(q)
			paged = append(paged, keys(lo)...)
			if !lo.IsTruncated {
				break
			}
			tok = lo.NextToken
		}
		if !sort.StringsAreSorted(paged) || !reflect.DeepEqual(full, paged) {
			t.Errorf("paging %q: %v vs %v", d, paged, full)
		}
	}

	// objects
	c, body, h := do("GET", "/bk/a.txt", true)
	if c != 200 || body != "hello world" || h.Get("ETag") == "" {
		t.Errorf("get: %d %q %v", c, body, h)
	}
	r, _ = http.NewRequest("GET", ts.URL+"/bk/a.txt", nil)
	r.Header.Set("Range", "bytes=0-4")
	signReq(r, tAccess, tSecret)
	resp, _ := http.DefaultClient.Do(r)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || string(b) != "hello" {
		t.Errorf("range: %d %q", resp.StatusCode, b)
	}
	if c, _, h := do("HEAD", "/bk/dir/b.txt", true); c != 200 || h.Get("Content-Length") != "3" {
		t.Errorf("head: %d %v", c, h)
	}
	if c, body, _ := do("GET", "/bk/%C3%A4.txt", true); c != 200 || body != "umlaut" {
		t.Errorf("umlaut: %d %q", c, body)
	}
	if c, body, _ := do("GET", "/bk/a%20b.txt", true); c != 200 || body != "space" {
		t.Errorf("space: %d %q", c, body)
	}

	// everything that must NOT work
	for _, p := range []string{"/bk/missing.txt", "/bk/dir/", "/bk/dir", "/bk/.zfs/hidden.txt", "/bk/dir/%2e%2e/a.txt",
		"/bk/..%2fa.txt", "/bk/link.txt", "/bk/bad%5Cname.txt"} {
		if c, _, _ := do("GET", p, true); c != 404 {
			t.Errorf("%s: want 404, got %d", p, c)
		}
	}
	for _, m := range []string{"PUT", "DELETE", "POST"} {
		if c, body, _ := do(m, "/bk/new.txt", true); c != 403 || !strings.Contains(body, "read-only") {
			t.Errorf("%s: %d %s", m, c, body)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new.txt")); err == nil {
		t.Error("a write got through")
	}
	if c, _, _ := do("GET", "/bk?acl", true); c != 501 {
		t.Errorf("acl: want 501, got %d", c)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < 9; i++ {
		l.fail("1.2.3.4", now)
	}
	if l.isBlocked("1.2.3.4", now) {
		t.Fatal("blocked too early")
	}
	l.fail("1.2.3.4", now)
	if !l.isBlocked("1.2.3.4", now) || l.isBlocked("1.2.3.4", now.Add(2*time.Minute)) || l.isBlocked("5.6.7.8", now) {
		t.Fatal("limiter logic wrong")
	}
}

func TestBucketNames(t *testing.T) {
	for _, n := range []string{"s3-storage-snaps", "disaster-recovery", "abc", "a1b"} {
		if validBucketName(n) != nil {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"ab", "Abc", "a_b", "-abc", "abc-", "a.b.c", "xn--abc", strings.Repeat("a", 64)} {
		if validBucketName(n) == nil {
			t.Errorf("%q should be invalid", n)
		}
	}
}
