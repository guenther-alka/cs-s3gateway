# Changelog

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
