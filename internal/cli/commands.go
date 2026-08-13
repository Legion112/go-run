package cli

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/apply"
	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

// FetchPrefixes writes a country prefix list from a local MMDB or MaxMind CSV download.
func FetchPrefixes(license, country, out, mmdbPath string) error {
	if mmdbPath != "" {
		return prefixes.FetchFromMMDB(mmdbPath, country, out)
	}
	return prefixes.FetchGeoLite2CountryCSV(license, country, out)
}

// FetchMaxMind downloads and writes a country prefix list (CSV). Kept for callers.
func FetchMaxMind(license, country, out string) error {
	return FetchPrefixes(license, country, out, "")
}

// Apply loads prefixes and reconciles kernel state.
func Apply(prefixesPath, endpoint, wgConfig, lanCSV string, tunnelUp bool) error {
	if prefixesPath == "" {
		return fmt.Errorf("-prefixes is required")
	}
	if endpoint == "" {
		return fmt.Errorf("-endpoint is required")
	}
	ep, err := netip.ParseAddr(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}

	var prefs []netip.Prefix
	st, err := os.Stat(prefixesPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		prefs, err = prefixes.ParseMaxMindCountryDir(prefixesPath, "RU")
	} else {
		prefs, err = prefixes.ParseCIDRFile(prefixesPath)
	}
	if err != nil {
		return err
	}

	var lans []netip.Prefix
	if lanCSV != "" {
		for _, p := range strings.Split(lanCSV, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			pref, err := netip.ParsePrefix(p)
			if err != nil {
				return err
			}
			lans = append(lans, pref)
		}
	}

	p := policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: policy.DefaultTunnelIface,
		TunnelEndpoint:  ep,
		LANs:            lans,
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		FailMode:        policy.FailClosed,
		TunnelUp:        tunnelUp,
	}

	if wgConfig != "" {
		cfg, err := loadWGQuick(wgConfig)
		if err != nil {
			return err
		}
		p.WireGuard = cfg
		if cfg.Peer.Endpoint != "" {
			// keep TunnelEndpoint as underlay IP from -endpoint
		}
	}

	res, err := apply.Reconcile(linux.ExecRunner{}, p)
	if err != nil {
		return err
	}
	fmt.Printf("gotun apply: %d changes\n", res.Changes)
	return nil
}

// Clear removes owned kernel objects.
func Clear() error {
	return apply.Clear(linux.ExecRunner{})
}

func loadWGQuick(path string) (policy.WireGuardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.WireGuardConfig{}, err
	}
	var cfg policy.WireGuardConfig
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch {
		case section == "[interface]" && k == "PrivateKey":
			cfg.PrivateKey = v
		case section == "[interface]" && k == "Address":
			// take first address
			addr := strings.Split(v, ",")[0]
			addr = strings.TrimSpace(addr)
			if p, err := netip.ParsePrefix(addr); err == nil {
				cfg.Address = p
			} else if a, err := netip.ParseAddr(addr); err == nil {
				cfg.Address = netip.PrefixFrom(a, 32)
			}
		case section == "[interface]" && k == "ListenPort":
			fmt.Sscanf(v, "%d", &cfg.ListenPort)
		case section == "[peer]" && k == "PublicKey":
			cfg.Peer.PublicKey = v
		case section == "[peer]" && k == "Endpoint":
			cfg.Peer.Endpoint = v
		case section == "[peer]" && k == "AllowedIPs":
			for _, p := range strings.Split(v, ",") {
				p = strings.TrimSpace(p)
				if pref, err := netip.ParsePrefix(p); err == nil {
					cfg.Peer.AllowedIPs = append(cfg.Peer.AllowedIPs, pref)
				}
			}
		case section == "[peer]" && k == "PersistentKeepalive":
			fmt.Sscanf(v, "%d", &cfg.Peer.PersistentKeepalive)
		}
	}
	return cfg, nil
}
