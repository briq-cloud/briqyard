package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeTar(t *testing.T, entries []tar.Header, bodies map[string]string) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range entries {
		h := h
		body := bodies[h.Name]
		h.Size = int64(len(body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	return &b
}

func TestExtractStaysInRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	archive := writeTar(t, []tar.Header{
		{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "etc/hello", Typeflag: tar.TypeReg, Mode: 0o644},
		// A symlink that escapes, then a file written through it.
		{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777},
		{Name: "escape/pwned", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "../../up", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "bin/sh", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "bin/ash", Typeflag: tar.TypeLink, Linkname: "bin/sh"},
		{Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0o666},
	}, map[string]string{"etc/hello": "hi\n", "escape/pwned": "x", "../../up": "y", "bin/sh": "#!"})
	n, err := Extract(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("wrote %d entries", n)
	}
	if b, err := os.ReadFile(filepath.Join(root, "etc/hello")); err != nil || string(b) != "hi\n" {
		t.Fatalf("etc/hello: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("a file was written outside the root through a symlink")
	}
	if _, err := os.Stat(filepath.Join(root, "up")); err != nil {
		t.Fatal("../../up should have landed at the root")
	}
	// The escaping link resolves inside the root, so the file lands under root/<outside path>.
	found := false
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Name() == "pwned" {
			found = true
		}
		return nil
	})
	if !found {
		t.Fatal("escape/pwned should have been written somewhere inside the root")
	}
	fi, err := os.Stat(filepath.Join(root, "bin/ash"))
	if err != nil || fi.Mode()&os.ModePerm != 0o755 {
		t.Fatalf("hardlink bin/ash: %v %v", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "dev/null")); err == nil {
		t.Fatal("device nodes must be skipped")
	}
}
