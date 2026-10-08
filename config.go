package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// bucket names: 3-63 chars, a-z 0-9 and "-", start and end with a letter or digit
var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func validBucketName(n string) error {
	if !bucketRe.MatchString(n) {
		return fmt.Errorf("invalid bucket name %q (3-63 chars of a-z 0-9 -, must start and end with a letter or digit)", n)
	}
	if strings.HasPrefix(n, "xn--") || strings.HasSuffix(n, "-s3alias") || strings.HasSuffix(n, "--ol-s3") {
		return fmt.Errorf("invalid bucket name %q (reserved prefix/suffix)", n)
	}
	return nil
}

// parseSpec splits "name=path" at the first "=" (the path may contain a drive letter like C:\x).
func parseSpec(spec string) (name, path string, err error) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 || i == len(spec)-1 {
		return "", "", fmt.Errorf("bad spec %q, expected name=path", spec)
	}
	name, path = spec[:i], spec[i+1:]
	if err = validBucketName(name); err != nil {
		return "", "", err
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", "", e
	}
	return name, abs, nil
}

// applyConf reads "flag=value" lines (# comments) and sets every flag that was not given on the
// command line. bucket= and snaps= may be repeated; their value is again name=path.
func applyConf(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	given := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			return fmt.Errorf("%s line %d: expected flag=value", file, n+1)
		}
		k, v := strings.TrimLeft(strings.TrimSpace(line[:i]), "-"), strings.TrimSpace(line[i+1:])
		if k == "conf" || k == "version" || given[k] {
			continue
		}
		if err := flag.Set(k, v); err != nil {
			return fmt.Errorf("%s line %d: %w", file, n+1, err)
		}
	}
	return nil
}

// snapPath returns the ZFS snapshot directory of a mounted dataset.
func snapPath(dataset string) string {
	return filepath.Join(dataset, ".zfs", "snapshot")
}

// realAbs is an absolute, symlink-resolved (best effort) path; folded to lower case where the file system
// is normally case-insensitive.
func realAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		a = p
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		a = r
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		a = strings.ToLower(a)
	}
	return filepath.Clean(a)
}

// isUnder reports whether p is root itself or lies below it.
func isUnder(root, p string) bool {
	rel, err := filepath.Rel(realAbs(root), realAbs(p))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// exposes returns the first protected file/folder (napp-it _cfg with server.auth and the TLS key ...)
// that a bucket rooted at root would make readable. server.auth holds more than the S3 secret
// (cluster/crypto key), so it must never be served, not even through an old snapshot.
func exposes(root string, protected []string) string {
	for _, p := range protected {
		if p != "" && isUnder(root, p) {
			return p
		}
	}
	return ""
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// loadSecret mirrors the RustFS start script of napp-it CS: first line of
// _cfg/server.auth, first 20 bytes = secret key (access key is fixed "s3admin").
func loadSecret(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(line, "\r")
	if len(line) > 20 {
		line = line[:20]
	}
	if line == "" {
		return "", fmt.Errorf("%s: first line is empty", file)
	}
	return line, nil
}
