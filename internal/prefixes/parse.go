package prefixes

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ParseCIDRList reads one CIDR per line (comments and blanks ignored).
func ParseCIDRList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", line, err)
		}
		if p.Addr().Is6() {
			continue // v1 IPv4 only
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// ParseCIDRFile loads a CIDR list from disk.
func ParseCIDRFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseCIDRList(f)
}

// ParseMaxMindCountryDir parses GeoLite2-Country-CSV style directories.
// Expects Locations-en.csv and Blocks-IPv4.csv in dir (or filenames passed).
func ParseMaxMindCountryDir(dir, countryISO string) ([]netip.Prefix, error) {
	locPath := findFile(dir, "Locations-en.csv", "GeoLite2-Country-Locations-en.csv")
	blocksPath := findFile(dir, "Blocks-IPv4.csv", "GeoLite2-Country-Blocks-IPv4.csv")
	if locPath == "" || blocksPath == "" {
		return nil, fmt.Errorf("maxmind: missing Locations-en.csv or Blocks-IPv4.csv in %s", dir)
	}

	geonames, err := loadCountryGeonames(locPath, countryISO)
	if err != nil {
		return nil, err
	}
	return loadBlocksForGeonames(blocksPath, geonames)
}

func findFile(dir string, names ...string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, n := range names {
			if e.Name() == n || strings.HasSuffix(e.Name(), n) {
				return filepath.Join(dir, e.Name())
			}
		}
	}
	// also try exact paths
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func loadCountryGeonames(path, iso string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idxID := indexOf(header, "geoname_id")
	idxISO := indexOf(header, "country_iso_code")
	if idxID < 0 || idxISO < 0 {
		return nil, fmt.Errorf("maxmind locations: missing geoname_id or country_iso_code columns")
	}
	want := strings.ToUpper(iso)
	out := map[string]struct{}{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) <= idxID || len(rec) <= idxISO {
			continue
		}
		if strings.ToUpper(rec[idxISO]) == want {
			out[rec[idxID]] = struct{}{}
		}
	}
	return out, nil
}

func loadBlocksForGeonames(path string, geonames map[string]struct{}) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idxNet := indexOf(header, "network")
	idxGeo := indexOf(header, "geoname_id")
	idxReg := indexOf(header, "registered_country_geoname_id")
	if idxNet < 0 {
		return nil, fmt.Errorf("maxmind blocks: missing network column")
	}
	var out []netip.Prefix
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) <= idxNet {
			continue
		}
		gid := ""
		if idxGeo >= 0 && idxGeo < len(rec) && rec[idxGeo] != "" {
			gid = rec[idxGeo]
		} else if idxReg >= 0 && idxReg < len(rec) {
			gid = rec[idxReg]
		}
		if _, ok := geonames[gid]; !ok {
			continue
		}
		p, err := netip.ParsePrefix(rec[idxNet])
		if err != nil {
			return nil, fmt.Errorf("maxmind network %q: %w", rec[idxNet], err)
		}
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out, nil
}

func indexOf(header []string, name string) int {
	for i, h := range header {
		if h == name {
			return i
		}
	}
	return -1
}

// WriteCIDRList writes prefixes one per line.
func WriteCIDRList(path string, prefixes []netip.Prefix) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, p := range prefixes {
		if _, err := fmt.Fprintln(f, p.String()); err != nil {
			return err
		}
	}
	return nil
}
