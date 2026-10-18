// Package image turns an OCI image into a root disk, once per image, and remembers its config.
package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/briq-cloud/briqyard/internal/storage"
)

// InitPath is where briqyard-init lives inside every root disk.
const InitPath = "/.briqyard/init"

// Config is what the image says about how to run it.
type Config struct {
	Entrypoint []string          `json:"entrypoint"`
	Cmd        []string          `json:"cmd"`
	Env        map[string]string `json:"env"`
	WorkDir    string            `json:"workdir"`
	User       string            `json:"user"`
	// Volumes the image declares (paths), so a data volume mounted there gets Docker's semantics.
	Volumes []string `json:"volumes"`
	// ExposedPorts the image declares.
	ExposedPorts []int `json:"exposed_ports"`
}

// Image is a built root disk.
type Image struct {
	// Ref as requested.
	Ref string `json:"ref"`
	// Digest of the image manifest.
	Digest string `json:"digest"`
	// Key is the dataset name under images/: digest plus the init's hash, shortened.
	Key      string    `json:"key"`
	Config   Config    `json:"config"`
	SizeGB   int       `json:"size_gb"`
	BuiltAt  time.Time `json:"built_at"`
	Platform string    `json:"platform"`
}

// Dataset is the storage name of the image's root disk.
func (i Image) Dataset() string { return "images/" + i.Key }

// Snap is the snapshot machines clone.
const Snap = "base"

// Builder makes root disks.
type Builder struct {
	Store storage.Backend
	// Dir keeps metadata and extraction scratch space.
	Dir string
	// Init is the briqyard-init binary.
	Init string
	// RootGB is every root disk's size.
	RootGB int
	Log    *slog.Logger

	mu       sync.Mutex
	building map[string]chan struct{}
	initHash string
}

// Ensure returns the built image for ref, pulling and building it when the host has not seen it.
// Concurrent calls for one image share a build.
func (b *Builder) Ensure(ctx context.Context, ref string) (Image, error) {
	if err := b.hashInit(); err != nil {
		return Image{}, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return Image{}, fmt.Errorf("image %q: %w", ref, err)
	}
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(platform)}
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return Image{}, fmt.Errorf("pull %s: %w", ref, err)
	}
	img, err := desc.Image()
	if err != nil {
		return Image{}, fmt.Errorf("pull %s: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return Image{}, err
	}
	key := b.key(digest.String())

	// One build at a time per key.
	b.mu.Lock()
	if b.building == nil {
		b.building = map[string]chan struct{}{}
	}
	if ch, ok := b.building[key]; ok {
		b.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return Image{}, ctx.Err()
		}
		return b.load(key)
	}
	ch := make(chan struct{})
	b.building[key] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.building, key)
		b.mu.Unlock()
		close(ch)
	}()

	if cached, err := b.load(key); err == nil {
		if ok, _ := b.Store.Exists(ctx, cached.Dataset()); ok {
			return cached, nil
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return Image{}, err
	}
	im := Image{Ref: ref, Digest: digest.String(), Key: key, SizeGB: b.RootGB, BuiltAt: time.Now().UTC(), Platform: platform.String()}
	im.Config = fromOCI(cfg)
	b.Log.Info("building image", "ref", ref, "digest", digest.String(), "key", key)
	if err := b.build(ctx, img, im); err != nil {
		_ = b.Store.Destroy(ctx, im.Dataset())
		return Image{}, err
	}
	if err := b.save(im); err != nil {
		return Image{}, err
	}
	return im, nil
}

func fromOCI(cfg *v1.ConfigFile) Config {
	c := Config{Entrypoint: cfg.Config.Entrypoint, Cmd: cfg.Config.Cmd, WorkDir: cfg.Config.WorkingDir, User: cfg.Config.User, Env: map[string]string{}}
	for _, kv := range cfg.Config.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			c.Env[k] = v
		}
	}
	for p := range cfg.Config.Volumes {
		c.Volumes = append(c.Volumes, p)
	}
	for p := range cfg.Config.ExposedPorts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			c.ExposedPorts = append(c.ExposedPorts, n)
		}
	}
	return c
}

func (b *Builder) hashInit() error {
	if b.initHash != "" {
		return nil
	}
	f, err := os.Open(b.Init)
	if err != nil {
		return fmt.Errorf("init binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	b.initHash = hex.EncodeToString(h.Sum(nil))
	return nil
}

func (b *Builder) key(digest string) string {
	h := sha256.Sum256([]byte(digest + "|" + b.initHash + "|" + fmt.Sprint(b.RootGB)))
	return hex.EncodeToString(h[:])[:20]
}

func (b *Builder) metaPath(key string) string { return filepath.Join(b.Dir, "meta", key+".json") }

func (b *Builder) load(key string) (Image, error) {
	var im Image
	data, err := os.ReadFile(b.metaPath(key))
	if err != nil {
		return im, err
	}
	return im, json.Unmarshal(data, &im)
}

func (b *Builder) save(im Image) error {
	if err := os.MkdirAll(filepath.Dir(b.metaPath(im.Key)), 0o750); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(im, "", "  ")
	return os.WriteFile(b.metaPath(im.Key), data, 0o640)
}

// build extracts the image to a scratch directory, adds the init, makes the disk and snapshots it.
func (b *Builder) build(ctx context.Context, img v1.Image, im Image) error {
	scratch, err := os.MkdirTemp(filepath.Join(b.Dir), "extract-*")
	if err != nil {
		if err := os.MkdirAll(b.Dir, 0o750); err != nil {
			return err
		}
		if scratch, err = os.MkdirTemp(b.Dir, "extract-*"); err != nil {
			return err
		}
	}
	defer os.RemoveAll(scratch)
	root := filepath.Join(scratch, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return err
	}
	rc := mutate.Extract(img)
	n, err := Extract(root, rc)
	rc.Close()
	if err != nil {
		return fmt.Errorf("extract %s: %w", im.Ref, err)
	}
	if err := b.prepareRoot(root); err != nil {
		return err
	}
	dev, err := b.Store.Create(ctx, im.Dataset(), int64(b.RootGB)<<30)
	if err != nil {
		return err
	}
	// mkfs.ext4 -d populates the filesystem from the directory, as root, without mounting.
	cmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-F", "-L", "root", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-d", root, dev)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 %s: %s", dev, strings.TrimSpace(string(out)))
	}
	if err := b.Store.Snapshot(ctx, im.Dataset(), Snap); err != nil {
		return err
	}
	b.Log.Info("image built", "ref", im.Ref, "files", n, "dataset", im.Dataset())
	return nil
}

// prepareRoot adds what every guest needs: the init, mount points, writable name files.
func (b *Builder) prepareRoot(root string) error {
	for _, d := range []string{"proc", "sys", "dev", "run", "tmp", "etc", ".briqyard"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return err
		}
	}
	_ = os.Chmod(filepath.Join(root, "tmp"), 0o1777)
	in, err := os.Open(b.Init)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(root, InitPath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// The init rewrites these at boot; a symlink (Debian's resolv.conf) or a missing file would
	// make that write land elsewhere or fail.
	for _, f := range []string{"etc/hosts", "etc/resolv.conf", "etc/hostname"} {
		p := filepath.Join(root, f)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(p)
		}
		if _, err := os.Lstat(p); err != nil {
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}
