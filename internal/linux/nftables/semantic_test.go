package nftables

import (
	"net/netip"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func TestSemanticMatchJSON_ExactElements(t *testing.T) {
	spec := policy.NftSpec{
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
					ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
					ExcludeAddrs:    []netip.Addr{netip.MustParseAddr("10.10.0.2")},
					DirectSet:       "ru_nets",
					Mark:            1,
				},
			},
		}},
	}
	good := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if !semanticMatchJSON(good, spec) {
		t.Fatal("expected match")
	}

	extra := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24","10.200.2.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(extra, spec) {
		t.Fatal("extra prefix must not match")
	}

	sameCountDiff := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.9.9.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(sameCountDiff, spec) {
		t.Fatal("same count different contents must not match")
	}

	wrongMark := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":2}}]}}
]}`
	if semanticMatchJSON(wrongMark, spec) {
		t.Fatal("wrong mark must not match")
	}
}
