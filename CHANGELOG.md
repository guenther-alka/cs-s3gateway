# Changelog

## 0.3.1

- Login with an own session secret as an alternative to the RustFS secret (`--creds-from <file>`, e.g. created on demand by the napp-it CS menu). The log tells where the secret was read from.

## 0.3.0

- New bucket types `--rust` / `--rustsnaps`: read RustFS on-disk data (xl.meta, inline data, multipart) and present objects as normal files, also inside ZFS snapshots.
- Objects the reader cannot decode (compressed, encrypted, tiered, multi disk) answer 501 with a reason.
- ETag and content type of RustFS objects come from the metadata.

## 0.2.1

Security audit, see [SECURITY.md](SECURITY.md):

- `.zfs` stays hidden under every alias on case-insensitive / aliasing file systems (`.ZFS`, `.zfs.`, `ZFS~1`)
- buckets that would expose napp-it's `_cfg` (server.auth, TLS key), also through snapshots of its dataset, are refused at start
- every file response (S3 GET and web page) carries `CSP: sandbox`, `nosniff`, `CORP`; active types are always `attachment`
- failed-login limiter: challenge request without credentials no longer counts, IPv6 grouped by /64, table pruning keeps active blocks
- web pages: `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `base-uri`/`form-action` none

## 0.2.0

- Built-in read-only web page (`/_browse/`, also `/` for browsers): bucket list, folder listing, download. HTTP Basic login with the same credentials as S3.
- html/svg and other active types are never rendered inline (attachment + CSP sandbox), `.zfs` hidden, same failed-login limiter.
- `openRegular` shared by S3 GET and the web page.

## 0.1.0 - 2026-10-08

First version.

* read-only S3 (list v1/v2, head, get with ranges, presigned URLs) for folders and `.zfs/snapshot`
* SigV4 authentication, credentials and PEM taken from napp-it CS / RustFS
* `--bucket`, `--snaps` (repeatable), `--idle-timeout`, `--log`
* `os.Root` folder jail, failed-login limiter, audit log line per request
* tested with the AWS SigV4 documentation examples and with boto3 (list, paging, get, range, presigned, write denial)
