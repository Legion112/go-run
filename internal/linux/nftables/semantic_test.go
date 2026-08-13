package nftables

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func baseMarkSpec(lan, endpoint string) policy.NftSpec {
	return policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{{
			Name: "ru_nets",
			Type: "ipv4_addr",
			Elements: []netip.Prefix{
				netip.MustParsePrefix("10.200.0.0/24"),
				netip.MustParsePrefix("10.200.1.0/24"),
			},
		}},
		Chains: []policy.NftChainSpec{{
			Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -150, Policy: "accept",
			Rules: []policy.NftRuleSpec{
				{Description: "drop-ipv6", DropIPv6: true},
				{
					Description:     "mark-non-direct",
					ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix(lan)},
					ExcludeAddrs:    []netip.Addr{netip.MustParseAddr(endpoint)},
					DirectSet:       "ru_nets",
					Mark:            1,
				},
			},
		}},
	}
}

func nftJSONWithExclusions(lanPrefix, endpoint string) string {
	// lanPrefix like "10.10.0.0/24" — split for JSON prefix object
	p := netip.MustParsePrefix(lanPrefix)
	return fmt.Sprintf(`{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"%s","len":%d}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"%s"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`, p.Addr().String(), p.Bits(), endpoint)
}

func TestSemanticMatchJSON_ExactElements(t *testing.T) {
	spec := baseMarkSpec("10.10.0.0/24", "10.10.0.2")
	good := nftJSONWithExclusions("10.10.0.0/24", "10.10.0.2")
	if !semanticMatchJSON(good, spec) {
		t.Fatal("expected match")
	}

	extra := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24","10.200.2.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(extra, spec) {
		t.Fatal("extra prefix must not match")
	}

	sameCountDiff := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.9.9.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(sameCountDiff, spec) {
		t.Fatal("same count different contents must not match")
	}

	wrongMark := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":2}}]}}
]}`
	if semanticMatchJSON(wrongMark, spec) {
		t.Fatal("wrong mark must not match")
	}
}

func TestSemanticMatchJSON_DifferentEndpointDoesNotMatch(t *testing.T) {
	spec := baseMarkSpec("10.10.0.0/24", "5.6.7.8")
	live := nftJSONWithExclusions("10.10.0.0/24", "1.2.3.4")
	if semanticMatchJSON(live, spec) {
		t.Fatal("different exclude-endpoint daddr must not match")
	}
}

func TestSemanticMatchJSON_DifferentLANDoesNotMatch(t *testing.T) {
	spec := baseMarkSpec("192.168.50.0/24", "10.10.0.2")
	live := nftJSONWithExclusions("192.168.1.0/24", "10.10.0.2")
	if semanticMatchJSON(live, spec) {
		t.Fatal("different exclude-lan prefix must not match")
	}
}
