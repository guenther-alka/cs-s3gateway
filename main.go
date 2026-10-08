// cs-s3gateway - read-only S3 gateway for folders and ZFS snapshots (part of napp-it CS).
//
// Exports ordinary folders as S3 buckets: key = relative path, no own data format.
// Typical use: <dataset>/.zfs/snapshot as bucket, so all snapshots of a dataset are readable via S3.
// Only GET/HEAD/List are served, every write request is answered with AccessDenied.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const version = "0.3.0"

// kindSnap only exists while adding buckets: a plain bucket rooted in <dataset>/.zfs/snapshot
const kindSnap = 100

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func defaultBase() string {
	if runtime.GOOS == "windows" {
		return `C:\opt\csweb-gui`
	}
	return "/opt/csweb-gui"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cs-s3gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	var buckets, snaps, rusts, rustsnaps stringList
	listen := flag.String("listen", ":9100", "listen address")
	base := flag.String("base", defaultBase(), "napp-it CS folder; credentials and PEM are taken from its _cfg")
	credsFrom := flag.String("creds-from", "", "file with the RustFS secret in its first line (default <base>/_cfg/server.auth)")
	accessKey := flag.String("access-key", "", "access key (default s3admin or $CS_S3GW_ACCESS_KEY)")
	certF := flag.String("cert", "", "TLS certificate PEM (default <base>/_cfg/s3/pem/rustfs_cert.pem)")
	keyF := flag.String("key", "", "TLS key PEM (default <base>/_cfg/s3/pem/rustfs_key.pem)")
	noTLS := flag.Bool("no-tls", false, "plain HTTP (testing only)")
	idle := flag.Duration("idle-timeout", 0, "exit after this time without requests, e.g. 30m (0 = run until stopped)")
	logFile := flag.String("log", "", "append log lines to this file as well as stdout")
	maxKeys := flag.Int("max-keys", 1000, "maximum keys per list response")
	showVer := flag.Bool("version", false, "print version")
	flag.Var(&buckets, "bucket", "name=folder  export a folder as bucket (repeatable)")
	flag.Var(&snaps, "snaps", "name=dataset-mountpoint  export <mountpoint>/.zfs/snapshot as bucket (repeatable)")
	flag.Var(&rusts, "rust", "name=folder  export a RustFS data folder (single disk) as bucket, objects shown as normal files (repeatable)")
	flag.Var(&rustsnaps, "rustsnaps", "name=dataset-mountpoint  like --rust for <mountpoint>/.zfs/snapshot/<snap>/<rustfs-bucket>/... (repeatable)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "cs-s3gateway %s - read-only S3 gateway for folders and ZFS snapshots\n\nusage: cs-s3gateway [flags]\n\n", version)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nenvironment: CS_S3GW_ACCESS_KEY, CS_S3GW_SECRET_KEY (instead of server.auth)")
	}
	conf := flag.String("conf", "", "config file with one flag=value per line (e.g. listen=:9100, snaps=name=/pool/fs); command line wins")
	flag.Parse()
	if *conf != "" {
		if err := applyConf(*conf); err != nil {
			return err
		}
	}
	if *showVer {
		fmt.Println("cs-s3gateway", version)
		return nil
	}

	// output
	var out io.Writer = os.Stdout
	if *logFile != "" {
		lf, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer lf.Close()
		out = io.MultiWriter(os.Stdout, lf)
	}
	logger := log.New(out, "", log.Ldate|log.Ltime)

	// credentials
	access := *accessKey
	if access == "" {
		access = os.Getenv("CS_S3GW_ACCESS_KEY")
	}
	if access == "" {
		access = "s3admin"
	}
	secret := os.Getenv("CS_S3GW_SECRET_KEY")
	if secret == "" {
		cf := *credsFrom
		if cf == "" {
			cf = filepath.Join(*base, "_cfg", "server.auth")
		}
		s, err := loadSecret(cf)
		if err != nil {
			return fmt.Errorf("no credentials: %w", err)
		}
		secret = s
	}

	// buckets
	if len(buckets)+len(snaps)+len(rusts)+len(rustsnaps) == 0 {
		return errors.New("no bucket configured, use --bucket name=folder or --snaps name=dataset-mountpoint")
	}
	g := &gateway{buckets: map[string]*bucket{}, access: access, secret: secret, maxKeys: *maxKeys,
		logger: logger, started: time.Now(), now: time.Now, lim: newLimiter()}
	if g.maxKeys < 1 || g.maxKeys > 1000 {
		g.maxKeys = 1000
	}
	protected := []string{filepath.Join(*base, "_cfg")}
	if *credsFrom != "" {
		protected = append(protected, *credsFrom)
	}
	if *keyF != "" {
		protected = append(protected, *keyF)
	}
	add := func(spec string, kind int) error {
		snap := kind == kindSnap || kind == kindRustSnap
		name, p, err := parseSpec(spec)
		if err != nil {
			return err
		}
		dsRoot := p // for snapshots the whole dataset counts: old snapshots contain old copies of the files
		if snap {
			p = snapPath(p)
		}
		if bad := exposes(dsRoot, protected); bad != "" {
			return fmt.Errorf("bucket %q: %s would expose %s (napp-it configuration, secrets or TLS key); export a different folder", name, dsRoot, bad)
		}
		if g.buckets[name] != nil {
			return fmt.Errorf("duplicate bucket name %q", name)
		}
		if !isDir(p) {
			if snap {
				return fmt.Errorf("bucket %q: %s not found (is the dataset mounted?)", name, p)
			}
			return fmt.Errorf("bucket %q: %s is not a folder", name, p)
		}
		root, err := os.OpenRoot(p)
		if err != nil {
			return fmt.Errorf("bucket %q: %w", name, err)
		}
		bk := &bucket{name: name, path: p, root: root}
		switch kind {
		case kindRust:
			bk.kind = kindRust
		case kindRustSnap:
			bk.kind, bk.bucketIdx = kindRustSnap, 1
		}
		g.buckets[name] = bk
		return nil
	}
	for _, s := range buckets {
		if err := add(s, kindPlain); err != nil {
			return err
		}
	}
	for _, s := range snaps {
		if err := add(s, kindSnap); err != nil {
			return err
		}
	}
	for _, s := range rusts {
		if err := add(s, kindRust); err != nil {
			return err
		}
	}
	for _, s := range rustsnaps {
		if err := add(s, kindRustSnap); err != nil {
			return err
		}
	}
	g.names = sortedNames(g.buckets)

	// TLS
	srv := &http.Server{
		Addr:              *listen,
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          logger,
	}
	useTLS := !*noTLS
	if useTLS {
		cert, key := *certF, *keyF
		if cert == "" {
			cert = filepath.Join(*base, "_cfg", "s3", "pem", "rustfs_cert.pem")
		}
		if key == "" {
			key = filepath.Join(*base, "_cfg", "s3", "pem", "rustfs_key.pem")
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("TLS: %w (use --no-tls for plain HTTP)", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}

	logger.Printf("cs-s3gateway %s starting on %s (%s), access key %q, read-only", version, *listen, map[bool]string{true: "https", false: "http - NO TLS"}[useTLS], access)
	for _, n := range g.names {
		logger.Printf("bucket %s -> %s", n, g.buckets[n].path)
	}
	if *idle > 0 {
		logger.Printf("idle timeout %s", *idle)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		errc <- err
	}()

	g.lastUse.Store(time.Now().UnixNano())
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
			logger.Printf("stopping (signal)")
			return shutdown(srv)
		case <-tick.C:
			if *idle > 0 && g.active.Load() == 0 &&
				time.Since(time.Unix(0, g.lastUse.Load())) >= *idle {
				logger.Printf("stopping (idle for %s)", *idle)
				return shutdown(srv)
			}
		}
	}
}

func shutdown(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
