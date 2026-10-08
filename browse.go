package main

import (
	"crypto/subtle"
	"fmt"
	"html"
	"mime"
	"net/http"
	"path"
	"strings"
)

// Built-in read-only web browser for the buckets (for use from a phone or any browser, "on the road").
// Namespace /_browse/ (a bucket name can never contain "_"), HTTP Basic auth with the same access key / secret as S3.
// Use it over HTTPS only: Basic auth sends the secret with every request.

const browsePrefix = "/_browse"
const browsePage = 500

func (g *gateway) basicOK(r *http.Request) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	a := subtle.ConstantTimeCompare([]byte(u), []byte(g.access))
	b := subtle.ConstantTimeCompare([]byte(p), []byte(g.secret))
	return a&b == 1
}

func isBrowseRequest(r *http.Request) bool {
	p := r.URL.Path
	if p == browsePrefix || strings.HasPrefix(p, browsePrefix+"/") {
		return true
	}
	// a browser opening the gateway root gets the web page instead of an S3 error
	return p == "/" && r.URL.RawQuery == "" && r.Header.Get("Authorization") == "" &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

func htmlPage(w http.ResponseWriter, title, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "private, no-store")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>%s</title><style>body{font-family:sans-serif;margin:16px}table{border-collapse:collapse}td,th{padding:4px 14px 4px 0;text-align:left}`+
		`a{text-decoration:none}small{color:#666}.hd{background:#d9d9d9;margin:-16px -16px 16px;padding:10px 16px;font-size:14px}</style></head>`+
		`<body><div class="hd"><b>cs-s3gateway v%s</b> (read only s3 access to snaps and regular folders)</div>%s</body></html>`,
		html.EscapeString(title), version, body)
}

func humanSize(n int64) string {
	const u = "KMGT"
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %cB", f, u[i])
}

func href(parts ...string) string {
	return html.EscapeString(browsePrefix + "/" + awsEncode(strings.Join(parts, "/"), false))
}

// browse serves the web pages; it returns true if the request was authenticated.
func (g *gateway) browse(w http.ResponseWriter, r *http.Request, ip string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return false
	}
	if r.URL.Path == "/" {
		http.Redirect(w, r, browsePrefix+"/", http.StatusFound)
		return false
	}
	if !g.basicOK(r) {
		g.lim.fail(ip, g.now())
		w.Header().Set("WWW-Authenticate", `Basic realm="cs-s3gateway", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	p := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, browsePrefix), "/")
	if p == "" {
		var sb strings.Builder
		sb.WriteString("<h3>Buckets</h3><ul>")
		for _, n := range g.names {
			sb.WriteString(`<li><a href="` + href(n) + `/">` + html.EscapeString(n) + `</a></li>`)
		}
		sb.WriteString("</ul>")
		htmlPage(w, "cs-s3gateway", sb.String())
		return true
	}
	name, rest := p, ""
	if i := strings.IndexByte(p, '/'); i >= 0 {
		name, rest = p[:i], p[i+1:]
	}
	b := g.buckets[name]
	if b == nil {
		http.Error(w, "no such bucket", http.StatusNotFound)
		return true
	}
	if rest == "" || strings.HasSuffix(rest, "/") {
		g.browseDir(w, r, b, rest)
		return true
	}
	g.browseFile(w, r, b, rest)
	return true
}

func (g *gateway) browseDir(w http.ResponseWriter, r *http.Request, b *bucket, prefix string) {
	if prefix != "" {
		for _, p := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
			if !validName(p) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}
		if strings.HasPrefix(prefix, ".zfs/") || prefix == ".zfs/" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	after := r.URL.Query().Get("after")
	items, truncated := b.list(prefix, "/", after, browsePage)

	var sb strings.Builder
	// breadcrumb
	sb.WriteString(`<p><a href="` + html.EscapeString(browsePrefix+"/") + `">Home</a> / <a href="` + href(b.name) + `/">` + html.EscapeString(b.name) + `</a>`)
	acc := b.name
	if prefix != "" {
		for _, seg := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
			acc += "/" + seg
			sb.WriteString(` / <a href="` + href(acc) + `/">` + html.EscapeString(seg) + `</a>`)
		}
	}
	sb.WriteString("</p><table><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr>")
	for _, e := range items {
		leaf := strings.TrimSuffix(strings.TrimPrefix(e.key, prefix), "/")
		if e.isPrefix {
			sb.WriteString(`<tr><td><a href="` + href(b.name, e.key) + `">` + html.EscapeString(leaf) + `/</a></td><td></td><td></td><td></td></tr>`)
		} else {
			sb.WriteString(`<tr><td><a href="` + href(b.name, e.key) + `">` + html.EscapeString(leaf) + `</a></td><td>` +
				humanSize(e.size) + `</td><td>` + e.mtime.Format("2006-01-02 15:04") +
				`</td><td><a href="` + href(b.name, e.key) + `?dl=1" download>Download</a></td></tr>`)
		}
	}
	sb.WriteString("</table>")
	if len(items) == 0 {
		sb.WriteString("<p><small>empty</small></p>")
	}
	if truncated && len(items) > 0 {
		last := items[len(items)-1].key
		sb.WriteString(`<p><a href="` + href(b.name, prefix) + `?after=` + html.EscapeString(awsEncode(last, true)) + `">more ...</a></p>`)
	}
	htmlPage(w, b.name+"/"+prefix, sb.String())
}

// types a browser may show inline; everything else is a download. The sandbox CSP keeps a file from running scripts.
var inlineTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
	"application/pdf": true, "text/plain": true}

func (g *gateway) browseFile(w http.ResponseWriter, r *http.Request, b *bucket, key string) {
	f, st, err := b.openRegular(key)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	ct := mime.TypeByExtension(strings.ToLower(path.Ext(key)))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cache-Control", "private, no-store")
	if !inlineTypes[ct] || r.URL.Query().Get("dl") == "1" {
		h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+awsEncode(path.Base(key), true))
	}
	http.ServeContent(w, r, "", st.ModTime(), f)
}
