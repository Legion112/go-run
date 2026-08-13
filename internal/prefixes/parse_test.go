package prefixes_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/legion/go-tun/internal/prefixes"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "prefixes")
}

func TestParseCIDRList(t *testing.T) {
	prefs, err := prefixes.ParseCIDRFile(filepath.Join(testdataDir(t), "ru-fixture.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefs))
	}
	if prefs[0].String() != "10.200.0.0/24" {
		t.Fatalf("got %s", prefs[0])
	}
}

func TestParseMaxMindCountryDir_RU(t *testing.T) {
	dir := testdataDir(t)
	prefs, err := prefixes.ParseMaxMindCountryDir(dir, "RU")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 2 {
		t.Fatalf("got %d RU prefixes: %v", len(prefs), prefs)
	}
	us, err := prefixes.ParseMaxMindCountryDir(dir, "US")
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 || us[0].String() != "198.51.100.0/24" {
		t.Fatalf("US prefixes: %v", us)
	}
}

func TestParseMaxMindCountryDir_Unknown(t *testing.T) {
	prefs, err := prefixes.ParseMaxMindCountryDir(testdataDir(t), "ZZ")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 0 {
		t.Fatalf("want empty, got %v", prefs)
	}
}

func TestWriteAndParseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src, err := prefixes.ParseMaxMindCountryDir(testdataDir(t), "RU")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	if err := prefixes.WriteCIDRList(out, src); err != nil {
		t.Fatal(err)
	}
	got, err := prefixes.ParseCIDRFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(src) {
		t.Fatalf("roundtrip len %d != %d", len(got), len(src))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
}
