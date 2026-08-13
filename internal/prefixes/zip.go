package prefixes

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractZip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name) //nolint:gosec
		cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
		if !strings.HasPrefix(filepath.Clean(target), cleanDest) && filepath.Clean(target) != filepath.Clean(dest) {
			return fmt.Errorf("illegal path in zip: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc) //nolint:gosec
		rc.Close()
		out.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}
