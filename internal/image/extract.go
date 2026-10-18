package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
)

// Extract writes a flattened image tar under root. Every path is resolved inside root
// (symlinks in the archive are never followed outside it), devices and sockets are skipped,
// ownership and modes are kept. It returns the number of entries written.
func Extract(root string, r io.Reader) (int, error) {
	tr := tar.NewReader(r)
	n := 0
	type link struct{ path, target string }
	var hardlinks []link
	var dirTimes []struct {
		path string
		t    time.Time
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return n, err
		}
		clean := strings.TrimPrefix(filepath.Clean("/"+hdr.Name), "/")
		if clean == "" || clean == "." {
			continue
		}
		// Whiteouts are applied by the flattening already; one that slipped through is skipped.
		if strings.HasPrefix(filepath.Base(clean), ".wh.") {
			continue
		}
		dest, err := securejoin.SecureJoin(root, clean)
		if err != nil {
			return n, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return n, err
		}
		mode := os.FileMode(hdr.Mode) & os.ModePerm
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, mode|0o700); err != nil {
				return n, err
			}
			if err := os.Chmod(dest, os.FileMode(hdr.Mode)&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)); err != nil {
				return n, err
			}
			dirTimes = append(dirTimes, struct {
				path string
				t    time.Time
			}{dest, hdr.ModTime})
		case tar.TypeReg, tar.TypeRegA:
			if err := os.RemoveAll(dest); err != nil {
				return n, err
			}
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return n, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return n, err
			}
			if err := f.Close(); err != nil {
				return n, err
			}
			if err := os.Chmod(dest, os.FileMode(hdr.Mode)&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)); err != nil {
				return n, err
			}
			_ = os.Chtimes(dest, hdr.ModTime, hdr.ModTime)
		case tar.TypeSymlink:
			_ = os.RemoveAll(dest)
			// The link's content is kept as is: the guest resolves it inside its own root.
			if err := os.Symlink(hdr.Linkname, dest); err != nil {
				return n, err
			}
		case tar.TypeLink:
			hardlinks = append(hardlinks, link{dest, strings.TrimPrefix(filepath.Clean("/"+hdr.Linkname), "/")})
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			continue
		default:
			continue
		}
		if hdr.Typeflag != tar.TypeSymlink {
			_ = os.Chown(dest, hdr.Uid, hdr.Gid)
		} else {
			_ = os.Lchown(dest, hdr.Uid, hdr.Gid)
		}
		n++
	}
	for _, l := range hardlinks {
		target, err := securejoin.SecureJoin(root, l.target)
		if err != nil {
			return n, err
		}
		_ = os.RemoveAll(l.path)
		if err := os.Link(target, l.path); err != nil {
			// A hard link to something skipped: copy nothing, keep going.
			continue
		}
		n++
	}
	for i := len(dirTimes) - 1; i >= 0; i-- {
		_ = os.Chtimes(dirTimes[i].path, dirTimes[i].t, dirTimes[i].t)
	}
	return n, nil
}
