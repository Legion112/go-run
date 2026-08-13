package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"net/netip"

	"github.com/legion/go-tun/internal/prefixes"
)

// ModuleRoot returns the go-tun module root directory.
func ModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/testutil -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// MMDBPath returns path to data/geo/GeoIP2-City.mmdb if it exists.
func MMDBPath(t *testing.T) (string, bool) {
	t.Helper()
	p := filepath.Join(ModuleRoot(t), "data", "geo", "GeoIP2-City.mmdb")
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// LoadAllRUfromMMDB extracts all RU IPv4 prefixes from the local City MMDB.
// Skips the test if the MMDB is missing.
func LoadAllRUfromMMDB(t *testing.T) []netip.Prefix {
	t.Helper()
	path, ok := MMDBPath(t)
	if !ok {
		t.Skip("local MMDB not available at data/geo/GeoIP2-City.mmdb")
	}
	prefs, err := prefixes.ExtractCountryFromMMDB(path, "RU")
	if err != nil {
		t.Fatalf("extract RU from MMDB: %v", err)
	}
	if len(prefs) < 1000 {
		t.Fatalf("expected >= 1000 RU prefixes from City MMDB, got %d", len(prefs))
	}
	for _, p := range prefs {
		if !p.IsValid() || !p.Addr().Is4() {
			t.Fatalf("invalid or non-IPv4 prefix: %v", p)
		}
	}
	return prefs
}
