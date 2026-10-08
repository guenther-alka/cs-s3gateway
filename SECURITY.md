# Security

## Reporting

Please report vulnerabilities privately through GitHub (*Security > Report a vulnerability* of this repository)
or by mail to guenther@napp-it.org. Do not open a public issue for a vulnerability.

## Threat model

cs-s3gateway is a **read-only** service. It has **one** credential pair (the RustFS admin keys of napp-it CS)
and is meant for a trusted LAN / VPN or behind a TLS terminating reverse proxy. Whoever knows the secret can
read every exported file; there are no per-user accounts. The service normally runs with the rights of the
napp-it CS server process (root / Administrator) so that it can read all snapshots. Exports are chosen by the
administrator, so everything below assumes a client that has **no** valid credentials, or valid credentials but
no right to leave the exported folders or to change anything.

## Audit 2026-10-08 (0.2.1)

A source review of all Go files plus the napp-it CS menu and a set of dynamic probes on Windows.

| # | finding | severity | status |
|---|---|---|---|
| 1 | `.zfs` hiding could be bypassed on Windows/macOS by an alias of the folder (`.ZFS`, `.zfs.`, `ZFS~1`) | medium | fixed: the first path component is compared with the real `.zfs` folder (`os.SameFile`) |
| 2 | a bucket rooted above napp-it's `_cfg` (e.g. `D:\` or `/opt`, or a snapshot of the dataset holding `_cfg`) would serve `server.auth` (more than the S3 secret: the cluster/crypto key) and the TLS key | medium | fixed: such buckets are refused at start |
| 3 | files served over a presigned S3 URL had no `Content-Security-Policy` / `nosniff`: an HTML file in an export, opened in a browser, would run on the gateway origin (where the web page login is cached) | medium | fixed: `CSP: sandbox`, `nosniff`, `attachment` for active types on every file response |
| 4 | the browser's first request without credentials counted as a failed login, so ten reloads locked the client out for a minute | low | fixed: only wrong credentials count |
| 5 | failed-login limiter: IPv6 addresses of one /64 could rotate to avoid the limit; the table was cleared completely when it grew | low | fixed: IPv6 grouped by /64, only expired entries are dropped |
| 6 | web pages could be framed (clickjacking) and read cross-origin | low | fixed: `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cross-Origin-Resource-Policy: same-origin`, `base-uri`/`form-action` none |
| 7 | napp-it CS menu: request values echoed into the page, curly quotes (U+2018..U+201F) in a bucket path act as quotes in PowerShell | low | fixed: values filtered, bucket paths reject quote look-alikes and shell metacharacters |

Checked and found sound: SigV4 verification (documented AWS test vectors, constant-time comparison, +-15 min skew,
signed `host`, all query parameters signed), folder jail (`os.Root`: `..`, absolute paths, symlinks, NTFS alternate
data streams and device names are rejected), only regular files are opened (`Lstat` first, no FIFO/device read),
names with backslash/control characters/invalid UTF-8 hidden, XML and HTML output escaped, quoted log lines (no
log injection), server timeouts and header size limits, TLS 1.2+, no writes anywhere, no secrets in logs, the
config file or the process list (`CS_S3GW_SECRET_KEY`).

## Known limitations (by design)

* One shared admin credential; no revocation other than changing `server.auth`.
* HTTP Basic login for the web page: use HTTPS. Browsers cache the credentials until closed (no logout).
* The 15 minute replay window of SigV4 header requests; presigned URLs are valid up to 7 days if the signer asked.
* Behind a reverse proxy all clients share the proxy's address, so failed logins of one user can lock out all
  (the limiter keys on the TCP peer address); give the proxy its own rate limit.
* On a `dir:` bucket a local writer could swap a file for a FIFO between the check and the open and stall one
  request (requires write access to the exported folder).
* Aliases of a file name (`a.txt.`, `A.TXT`, `LONGFO~1`) read the same file on Windows.
* Running as root/Administrator: a memory-safety bug in Go's standard library would have that reach. Keep Go current.

## RustFS reader (0.3.0)

- The xl.meta parser is a bounded msgpack decoder (size cap, panics are recovered and answered as 501).
- RustFS internals (`.rustfs.sys`, `xl.meta`, part files, anything inside an object folder) are neither listed nor addressable; all file access still goes through os.Root.
- Stored content types are reduced to a plain media type; the sandbox CSP and attachment rules for active types apply as for all files.
