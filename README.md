# cs-s3gateway

**Read-only S3 gateway for ZFS snapshots and ordinary folders** - part of [napp-it CS](https://www.napp-it.org).

cs-s3gateway exports folders as S3 buckets **without any data format of its own**: the object key is the relative
path, the files stay ordinary files (SMB, `ls`, backup tools keep seeing them as before). Its main use is the
snapshot directory of a ZFS dataset: **every snapshot of a dataset becomes a read-only top level folder in an S3
bucket**, reachable from WinSCP, rclone, restic, aws cli, boto3 - or from any browser through the built-in web page.

```
cs-s3gateway --snaps s3-storage-snaps=/pool/dataset --bucket disaster-recovery=/pool/dr
```

`s3-storage-snaps/daily_2026-10-07/Projekte/x.docx` is the file
`/pool/dataset/.zfs/snapshot/daily_2026-10-07/Projekte/x.docx`.

Why a separate tool? RustFS (and most S3 servers) keep their own object layout and have no read-only bucket or
"snapshot as bucket" option. A small separate service that only knows how to *read* is easier to audit than a
write-capable server, can be started on demand (with an idle timeout) and has no way to modify data.

* single static binary, Go standard library only, no dependencies
* Windows, Linux (amd64, arm64), macOS (amd64, arm64), FreeBSD, illumos, Solaris
* re-uses the credentials and the TLS certificate of RustFS in napp-it CS - nothing new to configure
* menu **System > Services > cs-s3gateway** in napp-it CS: start / stop / autostart / idle timeout / buckets

## Contents

1. [Quick start](#quick-start)
2. [How folders map to buckets](#how-folders-map-to-buckets)
3. [Credentials and certificates](#credentials-and-certificates)
4. [Options](#options)
5. [Config file](#config-file)
6. [Web page](#web-page)
7. [Clients](#clients)
8. [Supported S3 operations](#supported-s3-operations)
9. [Security model](#security-model)
10. [napp-it CS integration](#napp-it-cs-integration)
11. [Build and test](#build-and-test)
12. [Limits and status](#limits-and-status)
13. [License](#license)

## Quick start

Inside napp-it CS (credentials and PEM already exist from RustFS):

```
cs-s3gateway --snaps s3-storage-snaps=/tank/s3_storage --listen :9100 --idle-timeout 30m
```

Standalone, without TLS, with explicit credentials (testing):

```
set CS_S3GW_ACCESS_KEY=s3admin
set CS_S3GW_SECRET_KEY=0123456789abcdefghij
cs-s3gateway --no-tls --listen 127.0.0.1:9100 --bucket docs=D:\share\docs
```

Then open `http://127.0.0.1:9100/` in a browser or point an S3 client to `http://127.0.0.1:9100` (path style).

## How folders map to buckets

| option | exported folder | bucket content |
|---|---|---|
| `--bucket name=/folder` | `/folder` | the folder itself; key = relative path |
| `--snaps name=/pool/dataset` | `/pool/dataset/.zfs/snapshot` | one top level folder per snapshot |

* Both options are repeatable - several buckets on several folders are fine.
* **Bucket names** are 3-63 characters of `a-z 0-9 -`, start and end with a letter or digit. **Object keys** are
  arbitrary UTF-8 (umlauts, spaces, CJK ...), they are simply the file path with `/` as separator.
* `.zfs` belongs to **one dataset**. Snapshots of child datasets are in their own `.zfs`: give every dataset you
  want to reach its own `--snaps` bucket. The path is the *mounted* filesystem (`zfs get mountpoint`), on Windows
  e.g. `D:/s3_storage`.
* Only regular files and folders are visible. Symlinks, fifos, devices and sockets do not exist for the gateway.
  Names that cannot be addressed safely (backslash, control characters, invalid UTF-8) are hidden.
  In `--bucket` a top level `.zfs` is hidden.
* ZFS auto-mounts snapshots on first access; the first request into a snapshot can therefore be slower.

## Credentials and certificates

By default taken from napp-it CS exactly as the RustFS start script does:

* access key **`s3admin`**, secret = the first 20 bytes of the first line of `<base>/_cfg/server.auth`
  (the RustFS login), or an own **session secret**: `--creds-from <file> --access-key s3session` with a file that holds a random
  secret only this gateway knows. The napp-it CS menu creates it on demand (button *new secret*, setting *Login*), stores it in
  `_cfg/s3gw/s3gw.secret` and shows it in the login window; a new secret revokes the old one and restarts the service
  (System > Services > cs-s3gateway). The service table there lists the access key and a *Secret* column for both logins;
  secrets are never printed in the table, *show* opens them in a popup. Without a session secret the column offers *create*,
  otherwise *show* and *new* (with confirmation)
* certificate / key = `<base>/_cfg/s3/pem/rustfs_cert.pem` and `rustfs_key.pem`

So an S3 client that works with RustFS works with the gateway with the same keys - only the port differs
(RustFS 9000/9001, gateway 9100).

| setting | default | override |
|---|---|---|
| napp-it CS folder | `/opt/csweb-gui` (`C:\opt\csweb-gui` on Windows) | `--base` |
| secret file | `<base>/_cfg/server.auth` | `--creds-from file` |
| access key | `s3admin` | `--access-key`, env `CS_S3GW_ACCESS_KEY` |
| secret | from the secret file | env `CS_S3GW_SECRET_KEY` (keeps it out of the process list) |
| certificate / key | `<base>/_cfg/s3/pem/...` | `--cert`, `--key` |

## Options

| option | meaning |
|---|---|
| `--bucket name=folder` | export a folder, repeatable |
| `--snaps name=mountpoint` | export `<mountpoint>/.zfs/snapshot`, repeatable |
| `--listen :9100` | listen address (default `:9100`) |
| `--idle-timeout 30m` | exit after that time without requests (`0` = run until stopped) |
| `--log file` | append log lines to a file as well as stdout |
| `--max-keys 1000` | maximum keys per list response |
| `--no-tls` | plain HTTP (testing, or behind a TLS proxy) |
| `--base`, `--creds-from`, `--access-key`, `--cert`, `--key` | credentials and certificate, see above |
| `--conf file` | read options from a file, see below |
| `--version` | print the version |

## Config file

`--conf file` reads `flag=value` lines (`#` starts a comment). Options on the command line win over the file.
napp-it CS writes this file from its menu.

```
# s3gw.conf
listen=:9100
idle-timeout=30m
snaps=s3-storage-snaps=/tank/s3_storage
bucket=disaster-recovery=/tank/dr
```

The value of `snaps=` and `bucket=` is `name=path` (split at the first `=`). Secrets are never stored in this file.

## Web page

Since 0.2.0 the gateway has a small built-in read-only web page for use "on the road" from any browser or phone.
Open the gateway address (`https://host:9100/`, it redirects to `/_browse/`) and log in with the same access key and
secret. You get the bucket list, folder listings (500 entries per page) and per file:

* a click on the name shows `png jpeg gif webp pdf txt` directly in the browser, everything else is a download;
* the **Download** link always forces a download (`?dl=1`, `Content-Disposition: attachment`).

HTML, SVG and all other active content types are **never rendered**; every file response carries
`Content-Security-Policy: sandbox` and `X-Content-Type-Options: nosniff`, pages are `no-store`.
The web page uses HTTP Basic authentication, so **use it over HTTPS** (the default); the same failed-login limiter
as for S3 applies. The namespace `/_browse` cannot collide with a bucket (bucket names cannot contain `_`).

RustFS' own web console cannot show a foreign S3 endpoint, that is why the gateway brings its own page.

## Clients

Path style addressing only (`https://host:9100/bucket/key`), region `us-east-1`. For a self-signed certificate import
it or disable verification in the client.

**WinSCP** (tested, works) - File protocol *Amazon S3*, host name and port 9100, access key `s3admin` + secret,
Advanced > Environment > S3 > URL style **Path** (required: WinSCP defaults to virtual-host style, which the
gateway does not support, so *Path* must be selected); untick *Verify TLS certificate* for a self-signed certificate.

**rclone**

```
[snaps]
type = s3
provider = Other
endpoint = https://host:9100
access_key_id = s3admin
secret_access_key = <secret>
force_path_style = true
region = us-east-1
no_check_bucket = true
```

`rclone ls snaps:s3-storage-snaps/daily_2026-10-07`, `rclone copy snaps:s3-storage-snaps/daily_2026-10-07/Projekte /restore`

**aws cli**

```
aws s3 ls s3://s3-storage-snaps/ --endpoint-url https://host:9100 --no-verify-ssl
aws s3 cp s3://s3-storage-snaps/daily_2026-10-07/x.docx . --endpoint-url https://host:9100 --no-verify-ssl
```

**boto3**

```python
import boto3
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url="https://host:9100", aws_access_key_id="s3admin",
                  aws_secret_access_key="...", region_name="us-east-1", verify=False,
                  config=Config(s3={"addressing_style": "path"}))
for o in s3.list_objects_v2(Bucket="s3-storage-snaps", Delimiter="/").get("CommonPrefixes", []):
    print(o["Prefix"])
```

Presigned URLs (`aws s3 presign`, `generate_presigned_url`) work for GET and HEAD.

## Supported S3 operations

| operation | status |
|---|---|
| ListBuckets | yes |
| ListObjects (v1) / ListObjectsV2 | yes - prefix, delimiter, max-keys, continuation, `encoding-type=url` |
| GetObject / HeadObject | yes - `Range` and conditional headers (`If-Modified-Since`, ...) |
| GetBucketLocation, GetBucketVersioning | yes (always `us-east-1`, versioning not enabled) |
| presigned GET/HEAD (SigV4) | yes |
| other bucket sub-resources (ACL, policy, tagging, ...) | `501 NotImplemented` |
| PUT, POST, DELETE, multipart upload, copy | **`AccessDenied` - "cs-s3gateway is read-only"** |

ETags are derived from size and modification time (not an MD5 of the content), sufficient for caching and for
sync tools that compare size and time. Tools that insist on MD5 ETags can use their `--size-only` style options.

## Security model

* **Read only.** Only GET, HEAD and list are implemented; every other request is answered with `AccessDenied`.
  No code path writes to the exported folders. ZFS snapshots are immutable on top of that.
* **Folder jail.** All file access goes through Go's `os.Root`: no `..`, no symlink can leave the exported folder.
  Only regular files and folders are opened (a fifo or device can never block the server).
* **AWS Signature V4** for header and presigned requests, constant time comparison, +-15 minutes clock skew.
* **Brute force limiter.** 10 failed logins within a minute block the client address for a minute (S3 and web page).
* **TLS** (minimum 1.2) with the RustFS certificate; plain HTTP only with `--no-tls`.
* **Web page hardening.** Basic auth over TLS, strict CSP, `nosniff`, `sandbox` on file responses, HTML-escaped
  names, active content types are download-only, log lines print the request path quoted (`%q`).
* **Least privilege.** Run the service as an unprivileged user that can read the exported folders and the
  `_cfg` files and nothing else. The secret is not logged and not stored in the config file.
* **Audited.** Findings, fixes and known limitations: [SECURITY.md](SECURITY.md). Buckets that would expose the napp-it
  `_cfg` folder (server.auth, TLS key) are refused, `.zfs` stays hidden under every alias on Windows/macOS.
* **Idle timeout.** `--idle-timeout` makes the service end itself - an on-demand service is not an open port all day.
* **Exposure.** The gateway is meant for a trusted LAN/VPN or behind a reverse proxy. If you publish it to the
  internet, use HTTPS and a firewall/IP restriction as for any admin interface - it uses the *admin* credentials of
  RustFS (no per-user accounts yet).

## napp-it CS integration

napp-it CS (csweb-gui) contains the menu **System > Services > cs-s3gateway** which

* starts / stops the service, switches **autostart** on and off (started again with `server.pl` / at boot),
* sets port, **idle timeout** (never / 15 min ... 1 day), HTTPS yes/no,
* manages the bucket list (`snap:name=/pool/dataset`, `dir:name=/folder`; an empty list is pre-filled with the
  snapshots of the RustFS `s3_storage` filesystem),
* shows the endpoint, a link to the web page, and a **login** popup with access key and secret,
* writes `_cfg/s3gw/s3gw.conf` and keeps pid file and log next to it.

The binary is expected in `_my/tools/cs-s3gateway/<os>.amd64/` of napp-it CS.

## Build and test

Go 1.26 (the folder jail needs `os.Root`, Go 1.24+).

```
go vet ./... && go test ./...
powershell -NoProfile -File build-all.ps1 -Test
```

`build-all.ps1` produces 8 static variants (`CGO_ENABLED=0`, `-trimpath -s -w`) in `dist\release` plus
`checksums.sha256`. The tests cover the documented AWS Signature V4 examples (header and presigned), a complete
list/get/range/presign round trip including Unicode names, paging and the folder jail, the failed-login limiter,
bucket name validation and the web page (login, HTML escaping, download headers, traversal attempts).

## Limits and status

* read only by design - no uploads, no delete, no multipart, no versioning, no per-user accounts or bucket policies
* one set of credentials (the admin keys of RustFS)
* path style addressing only (no `bucket.host` virtual hosts)
* tested with the Go test suite, boto3, **WinSCP (URL style Path)** and the browser page on Windows; symlink handling and ZFS snapshot
  auto-mount behaviour on Linux and illumos still need field tests - reports welcome

## License

BSD 2-Clause, see [LICENSE](LICENSE). Changes: [CHANGELOG.md](CHANGELOG.md).

## RustFS data (v0.3.0)

RustFS keeps objects in its own format (a folder per object with `xl.meta` plus part files), not as plain files. Two bucket types read this format directly and present the objects as normal files:

```
cs-s3gateway --rust name=/s3_storage                 # a RustFS data folder: <rustfs-bucket>/<object>
cs-s3gateway --rustsnaps name=/tank/s3_storage       # <dataset>/.zfs/snapshot/<snapshot>/<rustfs-bucket>/<object>
```

In the napp-it CS menu use the bucket line types `rust:name=path` and `rustsnap:name=path`, for example `rustsnap:s3-storage-snaps=d:/s3_storage`.

Supported: single disk RustFS (`xl.meta` v2, inline data, multipart objects), nested keys, the latest version of versioned objects (delete markers hide the object), real ETag and content type from the metadata. The internal folders (`.rustfs.sys`, `xl.meta`, part files) are never visible or addressable.

Not supported (listed, but GET answers 501 with a reason): compressed or encrypted objects, tiered objects, erasure coded data spread over several disks. The bitrot checksums of the part files are skipped, not verified. Older versions of an object are not served.
