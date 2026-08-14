package amnezia

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Format selects the Amnezia site-based split-tunnel JSON shape.
type Format string

const (
	// FormatOfficial puts the CIDR in hostname (documented Amnezia / iplist format).
	FormatOfficial Format = "official"
	// FormatIOS puts the CIDR in ip with a placeholder hostname (iOS import workaround).
	FormatIOS Format = "ios"
)

// ParseFormat validates a -format flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatOfficial, "":
		return FormatOfficial, nil
	case FormatIOS:
		return FormatIOS, nil
	default:
		return "", fmt.Errorf("unknown format %q (want official|ios)", s)
	}
}

type site struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// EncodeSites builds Amnezia site-based split-tunnel JSON for the given prefixes.
func EncodeSites(prefs []netip.Prefix, format Format) ([]byte, error) {
	f, err := ParseFormat(string(format))
	if err != nil {
		return nil, err
	}
	sites := make([]site, 0, len(prefs))
	for i, p := range prefs {
		cidr := p.String()
		switch f {
		case FormatOfficial:
			sites = append(sites, site{Hostname: cidr, IP: ""})
		case FormatIOS:
			sites = append(sites, site{Hostname: fmt.Sprintf("site-%d", i+1), IP: cidr})
		}
	}
	return json.MarshalIndent(sites, "", "  ")
}

// WriteSites writes Amnezia site-based split-tunnel JSON to path.
func WriteSites(path string, prefs []netip.Prefix, format Format) error {
	data, err := EncodeSites(prefs, format)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
