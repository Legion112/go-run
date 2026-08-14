package amnezia

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestEncodeSitesOfficial(t *testing.T) {
	prefs := mustPrefs(t, "1.2.3.0/24", "10.0.0.0/8")
	data, err := EncodeSites(prefs, FormatOfficial)
	if err != nil {
		t.Fatal(err)
	}
	var sites []site
	if err := json.Unmarshal(data, &sites); err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("len=%d want 2", len(sites))
	}
	if sites[0].Hostname != "1.2.3.0/24" || sites[0].IP != "" {
		t.Fatalf("site0=%+v", sites[0])
	}
	if sites[1].Hostname != "10.0.0.0/8" || sites[1].IP != "" {
		t.Fatalf("site1=%+v", sites[1])
	}
}

func TestEncodeSitesIOS(t *testing.T) {
	prefs := mustPrefs(t, "1.2.3.0/24", "10.0.0.0/8")
	data, err := EncodeSites(prefs, FormatIOS)
	if err != nil {
		t.Fatal(err)
	}
	var sites []site
	if err := json.Unmarshal(data, &sites); err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("len=%d want 2", len(sites))
	}
	if sites[0].Hostname != "site-1" || sites[0].IP != "1.2.3.0/24" {
		t.Fatalf("site0=%+v", sites[0])
	}
	if sites[1].Hostname != "site-2" || sites[1].IP != "10.0.0.0/8" {
		t.Fatalf("site1=%+v", sites[1])
	}
}

func TestParseFormat(t *testing.T) {
	official, err := ParseFormat("official")
	if err != nil || official != FormatOfficial {
		t.Fatalf("official: %v %q", err, official)
	}
	ios, err := ParseFormat("ios")
	if err != nil || ios != FormatIOS {
		t.Fatalf("ios: %v %q", err, ios)
	}
	if _, err := ParseFormat("nope"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestWriteSites(t *testing.T) {
	prefs := mustPrefs(t, "192.0.2.0/24")
	path := filepath.Join(t.TempDir(), "sites.json")
	if err := WriteSites(path, prefs, FormatOfficial); err != nil {
		t.Fatal(err)
	}
	data, err := EncodeSites(prefs, FormatOfficial)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := string(data) + "\n"
	if string(got) != want {
		t.Fatalf("file=%q want=%q", got, want)
	}
}

func mustPrefs(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}
