// Package zfs is the ZFS storage backend: one zvol per disk, in one pool.
package zfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/briq-cloud/briqyard/internal/storage"
)

// Backend drives the zfs and zpool commands. Pool is the dataset every disk lives under
// ("byard", or "tank/briqyard").
type Backend struct {
	Pool string
	// Exec runs a command; tests replace it.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// New makes a backend on the pool and checks it exists.
func New(ctx context.Context, pool string) (*Backend, error) {
	b := &Backend{Pool: pool, Exec: run}
	if _, err := b.Exec(ctx, "zfs", "list", "-H", "-o", "name", pool); err != nil {
		return nil, fmt.Errorf("zfs pool %s: %w", pool, err)
	}
	// Parent datasets the layout needs.
	for _, d := range []string{"images", "m"} {
		if _, err := b.Exec(ctx, "zfs", "create", "-p", path.Join(pool, d)); err != nil {
			return nil, fmt.Errorf("zfs create %s/%s: %w", pool, d, err)
		}
	}
	return b, nil
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return out, nil
}

func (b *Backend) ds(name string) string { return path.Join(b.Pool, name) }

func devPath(ds string) string { return "/dev/zvol/" + ds }

func isMissing(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "dataset does not exist"))
}

func (b *Backend) Exists(ctx context.Context, name string) (bool, error) {
	_, err := b.Exec(ctx, "zfs", "list", "-H", "-o", "name", b.ds(name))
	if err == nil {
		return true, nil
	}
	if isMissing(err) {
		return false, nil
	}
	return false, err
}

func (b *Backend) Create(ctx context.Context, name string, sizeBytes int64) (string, error) {
	ok, err := b.Exists(ctx, name)
	if err != nil {
		return "", err
	}
	if !ok {
		// Parents first: "m/<id>/root" needs "m/<id>".
		if parent := path.Dir(name); parent != "." {
			if _, err := b.Exec(ctx, "zfs", "create", "-p", b.ds(parent)); err != nil {
				return "", err
			}
		}
		size := strconv.FormatInt(sizeBytes, 10)
		if _, err := b.Exec(ctx, "zfs", "create", "-s", "-V", size, "-b", "16K", "-o", "compression=lz4", b.ds(name)); err != nil {
			return "", err
		}
	}
	return b.waitDevice(ctx, name)
}

// waitDevice waits for udev to make the zvol's device node (asynchronous after create).
func (b *Backend) waitDevice(ctx context.Context, name string) (string, error) {
	dev := devPath(b.ds(name))
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(dev); err == nil {
			return dev, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("zvol device %s did not appear", dev)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (b *Backend) Device(ctx context.Context, name string) (string, error) {
	ok, err := b.Exists(ctx, name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", storage.ErrNotFound
	}
	return b.waitDevice(ctx, name)
}

func (b *Backend) Snapshot(ctx context.Context, name, snap string) error {
	_, err := b.Exec(ctx, "zfs", "snapshot", b.ds(name)+"@"+snap)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

func (b *Backend) Clone(ctx context.Context, name, snap, dest string) (string, error) {
	ok, err := b.Exists(ctx, dest)
	if err != nil {
		return "", err
	}
	if !ok {
		if parent := path.Dir(dest); parent != "." {
			if _, err := b.Exec(ctx, "zfs", "create", "-p", b.ds(parent)); err != nil {
				return "", err
			}
		}
		if _, err := b.Exec(ctx, "zfs", "clone", b.ds(name)+"@"+snap, b.ds(dest)); err != nil {
			return "", err
		}
	}
	return b.waitDevice(ctx, dest)
}

func (b *Backend) Destroy(ctx context.Context, name string) error {
	_, err := b.Exec(ctx, "zfs", "destroy", "-r", b.ds(name))
	if isMissing(err) {
		return nil
	}
	return err
}

func (b *Backend) DestroySnapshot(ctx context.Context, name, snap string) error {
	_, err := b.Exec(ctx, "zfs", "destroy", b.ds(name)+"@"+snap)
	if isMissing(err) {
		return nil
	}
	return err
}

func (b *Backend) Snapshots(ctx context.Context, name string) ([]string, error) {
	out, err := b.Exec(ctx, "zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-s", "creation", "-r", b.ds(name))
	if err != nil {
		if isMissing(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	var snaps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i := strings.Index(line, "@"); i > 0 && strings.TrimSuffix(line[:i], "/") == b.ds(name) {
			snaps = append(snaps, line[i+1:])
		}
	}
	return snaps, nil
}

func (b *Backend) Used(ctx context.Context, name string) (int64, error) {
	out, err := b.Exec(ctx, "zfs", "get", "-H", "-p", "-o", "value", "used", b.ds(name))
	if err != nil {
		if isMissing(err) {
			return 0, storage.ErrNotFound
		}
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
}

func (b *Backend) Free(ctx context.Context) (int64, error) {
	out, err := b.Exec(ctx, "zfs", "get", "-H", "-p", "-o", "value", "available", b.Pool)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
}

func (b *Backend) Promote(ctx context.Context, name string) error {
	_, err := b.Exec(ctx, "zfs", "promote", b.ds(name))
	return err
}

var _ storage.Backend = (*Backend)(nil)

// ErrNotFound re-exported for callers that only import this package.
var ErrNotFound = storage.ErrNotFound

func init() { _ = errors.New }
