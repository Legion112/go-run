package prefixes_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/legion/go-tun/internal/prefixes"
)

func TestExtractCountryFromMMDB_MissingFile(t *testing.T) {
	_, err := prefixes.ExtractCountryFromMMDB("/nonexistent/GeoIP2-City.mmdb", "RU")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestExtractCountryFromMMDB_InvalidFile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller failed")
	}
	// Use a non-MMDB file
	bad := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "prefixes", "ru-fixture.txt")
	_, err := prefixes.ExtractCountryFromMMDB(bad, "RU")
	if err == nil {
		t.Fatal("expected error for invalid mmdb")
	}
}

func TestExtractCountryFromMMDB_LiveOptional(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller failed")
	}
	mmdb := filepath.Join(filepath.Dir(thisFile), "..", "..", "data", "geo", "GeoIP2-City.mmdb")
	prefs, err := prefixes.ExtractCountryFromMMDB(mmdb, "RU")
	if err != nil {
		t.Skipf("local MMDB not available at data/geo/GeoIP2-City.mmdb: %v", err)
	}
	if len(prefs) < 100 {
		t.Fatalf("expected many RU prefixes from City MMDB, got %d", len(prefs))
	}
	for _, p := range prefs {
		if !p.Addr().Is4() {
			t.Fatalf("expected IPv4 only, got %s", p)
		}
	}
	t.Logf("extracted %d RU IPv4 prefixes", len(prefs))
}
