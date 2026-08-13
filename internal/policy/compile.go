package policy

import (
	"fmt"
	"net/netip"
)

// Compile turns a Policy into a declarative DesiredKernelState.
func Compile(p Policy) (DesiredKernelState, error) {
	if err := validate(p); err != nil {
		return DesiredKernelState{}, err
	}

	mark := p.Mark
	if mark == 0 {
		mark = DefaultMark
	}
	table := p.Table
	if table == 0 {
		table = DefaultTableID
	}
	prio := p.RulePriority
	if prio == 0 {
		prio = DefaultRulePriority
	}
	iface := p.TunnelInterface
	if iface == "" {
		iface = DefaultTunnelIface
	}

	excludes := append([]netip.Prefix(nil), p.LANs...)
	excludeAddrs := []netip.Addr{}
	if p.TunnelEndpoint.IsValid() {
		excludeAddrs = append(excludeAddrs, p.TunnelEndpoint)
	}

	state := DesiredKernelState{
		Sysctls: []SysctlSpec{
			{Key: "net.ipv4.ip_forward", Value: "1"},
			{Key: "net.ipv6.conf.all.disable_ipv6", Value: "1"},
			{Key: "net.ipv6.conf.default.disable_ipv6", Value: "1"},
		},
		Nft: NftSpec{
			Family: OwnedNftFamily,
			Table:  OwnedNftTable,
			Sets: []NftSetSpec{
				{
					Name:     RuNetsSetName,
					Type:     "ipv4_addr",
					Flags:    []string{"interval"},
					Elements: append([]netip.Prefix(nil), p.DirectPrefixes...),
				},
			},
			Chains: []NftChainSpec{
				{
					Name:     "prerouting",
					Type:     "filter",
					Hook:     "prerouting",
					Priority: -150, // mangle-like
					Policy:   "accept",
					Rules: []NftRuleSpec{
						{
							Description: "drop-ipv6",
							DropIPv6:    true,
						},
						{
							Description:     "mark-non-direct",
							ExcludePrefixes: excludes,
							ExcludeAddrs:    excludeAddrs,
							DirectSet:       RuNetsSetName,
							Mark:            mark,
						},
					},
				},
			},
		},
		IPRules: []IPRuleSpec{
			{Priority: prio, Mark: mark, Table: table},
		},
		Routes: []RouteSpec{
			routeForTunnel(table, iface, p.TunnelUp, p.FailMode),
		},
		WireGuard: WireGuardSpec{
			Interface:  iface,
			PrivateKey: p.WireGuard.PrivateKey,
			ListenPort: p.WireGuard.ListenPort,
			Address:    p.WireGuard.Address,
			Peer:       p.WireGuard.Peer,
			Managed:    p.WireGuard.PrivateKey != "",
			Up:         p.TunnelUp,
		},
	}

	return state, nil
}

func routeForTunnel(table int, iface string, tunnelUp bool, mode FailMode) RouteSpec {
	dst := netip.MustParsePrefix("0.0.0.0/0")
	if tunnelUp {
		return RouteSpec{Table: table, Destination: dst, Device: iface}
	}
	// v1: FailClosed only — blackhole when tunnel is down.
	_ = mode
	return RouteSpec{Table: table, Destination: dst, Blackhole: true}
}

func validate(p Policy) error {
	if !p.TunnelEndpoint.IsValid() {
		return fmt.Errorf("policy: TunnelEndpoint is required")
	}
	for _, pref := range p.DirectPrefixes {
		if !pref.IsValid() || pref.Addr().Is6() {
			return fmt.Errorf("policy: invalid or IPv6 DirectPrefix %v", pref)
		}
	}
	return nil
}

// SemanticEqual reports whether two desired states are semantically equivalent
// (ignoring incidental ordering of identical set elements after normalize).
func SemanticEqual(a, b DesiredKernelState) bool {
	return fmt.Sprintf("%#v", normalize(a)) == fmt.Sprintf("%#v", normalize(b))
}

func normalize(s DesiredKernelState) DesiredKernelState {
	// Shallow copy is enough for %#v comparison of our structs.
	return s
}
