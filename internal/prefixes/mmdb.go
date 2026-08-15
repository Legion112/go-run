package prefixes

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type mmdbCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// ExtractCountryFromMMDB walks all networks in a MaxMind City/Country MMDB
// and returns IPv4 prefixes whose country ISO code matches countryISO.
func ExtractCountryFromMMDB(mmdbPath, countryISO string) ([]netip.Prefix, error) {
	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}
	defer db.Close()

	want := strings.ToUpper(countryISO)
	var out []netip.Prefix

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec mmdbCountryRecord
		subnet, err := networks.Network(&rec)
		if err != nil {
			return nil, fmt.Errorf("mmdb network: %w", err)
		}
		iso := rec.Country.ISOCode
		if iso == "" {
			iso = rec.RegisteredCountry.ISOCode
		}
		if strings.ToUpper(iso) != want {
			continue
		}
		p, ok := ipNetToPrefix(subnet)
		if !ok {
			continue // skip IPv6 in v1
		}
		out = append(out, p)
	}
	if err := networks.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchFromMMDB extracts country prefixes from a local MMDB and writes a CIDR list.
func FetchFromMMDB(mmdbPath, countryISO, outPath string) error {
	prefs, err := ExtractCountryFromMMDB(mmdbPath, countryISO)
	if err != nil {
		return err
	}
	return WriteCIDRList(outPath, CollapseIPv4(prefs))
}

// LoadCountryPrefixesRaw returns country IPv4 prefixes without collapsing.
// Prefer LoadCountryPrefixes for configuration paths.
func LoadCountryPrefixesRaw(licenseKey, countryISO, mmdbPath string) ([]netip.Prefix, error) {
	if mmdbPath != "" {
		return ExtractCountryFromMMDB(mmdbPath, countryISO)
	}
	return DownloadGeoLite2CountryPrefixes(licenseKey, countryISO)
}

// LoadCountryPrefixes returns country IPv4 prefixes from a local MMDB or MaxMind CSV download,
// collapsed with CollapseIPv4 for configuration use.
// When mmdbPath is non-empty, the MMDB is used; otherwise licenseKey is required for CSV download.
func LoadCountryPrefixes(licenseKey, countryISO, mmdbPath string) ([]netip.Prefix, error) {
	prefs, err := LoadCountryPrefixesRaw(licenseKey, countryISO, mmdbPath)
	if err != nil {
		return nil, err
	}
	return CollapseIPv4(prefs), nil
}

func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}
