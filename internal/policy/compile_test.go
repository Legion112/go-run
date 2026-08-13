package policy_test

import (
	"net/netip"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func testPolicy(tunnelUp bool) policy.Policy {
	return policy.Policy{
		DirectPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.0/24"),
		},
		TunnelInterface: "wg0",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		FailMode:        policy.FailClosed,
		TunnelUp:        tunnelUp,
	}
}

func TestCompile_OwnedTableAndSet(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if st.Nft.Family != policy.OwnedNftFamily || st.Nft.Table != policy.OwnedNftTable {
		t.Fatalf("owned table: %s %s", st.Nft.Family, st.Nft.Table)
	}
	if len(st.Nft.Sets) != 1 || st.Nft.Sets[0].Name != policy.RuNetsSetName {
		t.Fatalf("sets: %+v", st.Nft.Sets)
	}
	if len(st.Nft.Sets[0].Elements) != 1 {
		t.Fatalf("elements: %v", st.Nft.Sets[0].Elements)
	}
}

func TestCompile_EndpointExcluded(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	var markRule *policy.NftRuleSpec
	for i := range st.Nft.Chains {
		for j := range st.Nft.Chains[i].Rules {
			if st.Nft.Chains[i].Rules[j].Description == "mark-non-direct" {
				markRule = &st.Nft.Chains[i].Rules[j]
			}
		}
	}
	if markRule == nil {
		t.Fatal("missing mark-non-direct rule")
	}
	if len(markRule.ExcludeAddrs) != 1 || markRule.ExcludeAddrs[0].String() != "10.10.0.2" {
		t.Fatalf("exclude addrs: %v", markRule.ExcludeAddrs)
	}
	if len(markRule.ExcludePrefixes) != 1 {
		t.Fatalf("exclude prefixes: %v", markRule.ExcludePrefixes)
	}
}

func TestCompile_FailClosedBlackhole(t *testing.T) {
	st, err := policy.Compile(testPolicy(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 1 || !st.Routes[0].Blackhole || st.Routes[0].Metric != policy.FailClosedRouteMetric {
		t.Fatalf("want lone blackhole metric %d, got %+v", policy.FailClosedRouteMetric, st.Routes)
	}
}

func TestCompile_TunnelUpKeepsFailClosedFallback(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 2 {
		t.Fatalf("want device + blackhole routes, got %+v", st.Routes)
	}
	var haveDev, haveBH bool
	for _, rt := range st.Routes {
		if rt.Device == "wg0" && rt.Metric == policy.TunnelRouteMetric && !rt.Blackhole {
			haveDev = true
		}
		if rt.Blackhole && rt.Metric == policy.FailClosedRouteMetric {
			haveBH = true
		}
	}
	if !haveDev || !haveBH {
		t.Fatalf("want wg0 metric %d + blackhole metric %d, got %+v",
			policy.TunnelRouteMetric, policy.FailClosedRouteMetric, st.Routes)
	}
}

func TestSemanticEqual_IgnoresPrefixOrder(t *testing.T) {
	a := testPolicy(true)
	b := testPolicy(true)
	b.DirectPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.200.1.0/24"),
		netip.MustParsePrefix("10.200.0.0/24"),
	}
	a.DirectPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.200.0.0/24"),
		netip.MustParsePrefix("10.200.1.0/24"),
	}
	sa, err := policy.Compile(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.SemanticEqual(sa, sb) {
		t.Fatal("expected equal after normalize despite prefix order")
	}
}

func TestCompile_RequiresEndpoint(t *testing.T) {
	p := testPolicy(true)
	p.TunnelEndpoint = netip.Addr{}
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("expected error")
	}
}

func TestSemanticEqual_SamePolicy(t *testing.T) {
	a, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.SemanticEqual(a, b) {
		t.Fatal("expected semantic equal")
	}
}
