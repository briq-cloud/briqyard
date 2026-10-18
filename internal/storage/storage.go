// Package storage is the disk layer: block devices for machines, with snapshots and clones.
package storage

import (
	"context"
	"errors"
)

// ErrNotFound is returned for a volume or snapshot that does not exist.
var ErrNotFound = errors.New("storage: not found")

// Backend makes and removes block devices. Names are paths under the backend's root
// ("images/abc", "m/<id>/root"); every method is idempotent where it can be.
type Backend interface {
	// Create makes a volume of sizeBytes (thin: unwritten blocks cost nothing) and returns its
	// device path. An existing volume of that name is returned as is.
	Create(ctx context.Context, name string, sizeBytes int64) (device string, err error)
	// Device is the block device of an existing volume.
	Device(ctx context.Context, name string) (string, error)
	// Exists says whether the volume exists.
	Exists(ctx context.Context, name string) (bool, error)
	// Snapshot takes a point-in-time snapshot `name@snap`.
	Snapshot(ctx context.Context, name, snap string) error
	// Clone makes a writable volume from a snapshot; the clone shares unchanged blocks with it.
	Clone(ctx context.Context, name, snap, dest string) (device string, err error)
	// Destroy removes a volume with its snapshots. Missing is success. A volume that still has
	// clones is an error unless the clones are destroyed first.
	Destroy(ctx context.Context, name string) error
	// DestroySnapshot removes one snapshot. Missing is success.
	DestroySnapshot(ctx context.Context, name, snap string) error
	// Snapshots lists a volume's snapshot names.
	Snapshots(ctx context.Context, name string) ([]string, error)
	// Used is the space a volume (and its snapshots) takes, in bytes.
	Used(ctx context.Context, name string) (int64, error)
	// Free is the space left in the backend, in bytes.
	Free(ctx context.Context) (int64, error)
	// Promote makes a clone independent of its origin's snapshot, so the origin can be destroyed.
	Promote(ctx context.Context, name string) error
}
