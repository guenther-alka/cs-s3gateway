package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	algo         = "AWS4-HMAC-SHA256"
	emptySHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedBody = "UNSIGNED-PAYLOAD"
	maxSkew      = 15 * time.Minute
	maxPresign   = 7 * 24 * time.Hour
)

// awsEncode is the SigV4 URI encoding: everything except A-Za-z0-9-_.~ is %XX (upper case).
func awsEncode(s string, encodeSlash bool) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func canonicalQuery(raw string, presigned bool) string {
	vals, _ := url.ParseQuery(raw)
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range vals {
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		for _, v := range vs {
			pairs = append(pairs, kv{awsEncode(k, true), awsEncode(v, true)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

func trimSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// canonicalRequest builds the SigV4 canonical request for r.
func canonicalRequest(r *http.Request, signedHeaders []string, payloadHash string, presigned bool) string {
	uri := awsEncode(r.URL.Path, false)
	if uri == "" {
		uri = "/"
	}
	var hb strings.Builder
	for _, h := range signedHeaders {
		var v string
		if h == "host" {
			v = trimSpaces(r.Host)
		} else {
			var vs []string
			for _, x := range r.Header.Values(h) {
				vs = append(vs, trimSpaces(x))
			}
			v = strings.Join(vs, ",")
		}
		hb.WriteString(h + ":" + v + "\n")
	}
	return r.Method + "\n" + uri + "\n" + canonicalQuery(r.URL.RawQuery, presigned) + "\n" +
		hb.String() + "\n" + strings.Join(signedHeaders, ";") + "\n" + payloadHash
}

func stringToSign(amzDate, scope, canonical string) string {
	h := sha256.Sum256([]byte(canonical))
	return algo + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
}

func errDenied(msg string) *apiErr { return &apiErr{403, "AccessDenied", msg} }

// authenticate verifies a SigV4 request (Authorization header or presigned URL).
func (g *gateway) authenticate(r *http.Request) *apiErr {
	q := r.URL.Query()
	var credential, signedStr, signature, amzDate, payload string
	presigned := false
	var expires time.Duration

	if auth := r.Header.Get("Authorization"); auth != "" {
		if !strings.HasPrefix(auth, algo+" ") {
			return errDenied("unsupported authorization type")
		}
		for _, f := range strings.Split(auth[len(algo)+1:], ",") {
			f = strings.TrimSpace(f)
			switch {
			case strings.HasPrefix(f, "Credential="):
				credential = f[len("Credential="):]
			case strings.HasPrefix(f, "SignedHeaders="):
				signedStr = f[len("SignedHeaders="):]
			case strings.HasPrefix(f, "Signature="):
				signature = f[len("Signature="):]
			}
		}
		amzDate = r.Header.Get("X-Amz-Date")
		if amzDate == "" {
			if t, err := http.ParseTime(r.Header.Get("Date")); err == nil {
				amzDate = t.UTC().Format("20060102T150405Z")
			}
		}
		payload = r.Header.Get("X-Amz-Content-Sha256")
		if payload == "" {
			payload = emptySHA256
		}
	} else if q.Get("X-Amz-Algorithm") != "" {
		if q.Get("X-Amz-Algorithm") != algo {
			return errDenied("unsupported algorithm")
		}
		presigned = true
		credential, signedStr, signature = q.Get("X-Amz-Credential"), q.Get("X-Amz-SignedHeaders"), q.Get("X-Amz-Signature")
		amzDate = q.Get("X-Amz-Date")
		n, err := strconv.Atoi(q.Get("X-Amz-Expires"))
		if err != nil || n < 1 || time.Duration(n)*time.Second > maxPresign {
			return &apiErr{400, "AuthorizationQueryParametersError", "X-Amz-Expires must be 1..604800"}
		}
		expires = time.Duration(n) * time.Second
		payload = unsignedBody
		if p := q.Get("X-Amz-Content-Sha256"); p != "" {
			payload = p
		}
	} else {
		return errDenied("Access Denied.")
	}
	if credential == "" || signedStr == "" || signature == "" || amzDate == "" {
		return errDenied("malformed authorization")
	}

	// credential = ACCESS/DATE/REGION/SERVICE/aws4_request
	cp := strings.Split(credential, "/")
	if len(cp) < 5 {
		return errDenied("malformed credential")
	}
	access := strings.Join(cp[:len(cp)-4], "/")
	date, region, service, term := cp[len(cp)-4], cp[len(cp)-3], cp[len(cp)-2], cp[len(cp)-1]
	if service != "s3" || term != "aws4_request" || len(date) != 8 || !strings.HasPrefix(amzDate, date) {
		return errDenied("malformed credential scope")
	}
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return errDenied("malformed date")
	}
	now := g.now()
	if presigned {
		if t.After(now.Add(maxSkew)) || now.After(t.Add(expires)) {
			return errDenied("Request has expired")
		}
	} else if d := now.Sub(t); d > maxSkew || d < -maxSkew {
		return &apiErr{403, "RequestTimeTooSkewed", "The difference between the request time and the server time is too large."}
	}
	if subtle.ConstantTimeCompare([]byte(access), []byte(g.access)) != 1 {
		return &apiErr{403, "InvalidAccessKeyId", "The access key ID you provided does not exist."}
	}

	signed := strings.Split(strings.ToLower(signedStr), ";")
	hasHost := false
	for _, h := range signed {
		if h == "host" {
			hasHost = true
		}
	}
	if !hasHost {
		return errDenied("host must be a signed header")
	}
	scope := strings.Join(cp[len(cp)-4:], "/")
	canon := canonicalRequest(r, signed, payload, presigned)
	want := hex.EncodeToString(hmacSHA256(signingKey(g.secret, date, region, service), stringToSign(amzDate, scope, canon)))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(signature))) {
		return &apiErr{403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided."}
	}
	return nil
}
