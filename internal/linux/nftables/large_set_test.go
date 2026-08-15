package nftables_test

import (
	"strings"
	"testing"
	"time"

	"net/netip"

	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/testutil"
)

func TestRenderFullTable_BatchesElements(t *testing.T) {
	els := make([]netip.Prefix, nftables.ElementBatchSize+10)
	for i := range els {
		els[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32)
	}
	script := nftables.RenderFullTable(policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{{
			Name:     "ru_nets",
			Type:     "ipv4_addr",
			Flags:    []string{"interval"},
			Elements: els,
		}},
	})
	if c := strings.Count(script, "add element"); c < 2 {
		t.Fatalf("expected multiple add element batches, got %d", c)
	}
}

func TestLargeRUSet_CompileAndRender(t *testing.T) {
	prefs := testutil.LoadAllRUfromMMDB(t)

	start := time.Now()
	st, err := policy.Compile(policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.20.0.3"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		FailMode:        policy.FailClosed,
		TunnelUp:        false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Nft.Sets) != 1 || len(st.Nft.Sets[0].Elements) != len(prefs) {
		t.Fatalf("compile elements: got %d want %d", len(st.Nft.Sets[0].Elements), len(prefs))
	}

	renderStart := time.Now()
	script := nftables.RenderFullTable(st.Nft)
	renderDur := time.Since(renderStart)

	if !strings.Contains(script, "ru_nets") {
		t.Fatal("script missing ru_nets")
	}
	batches := strings.Count(script, "add element")
	wantBatches := (len(prefs) + nftables.ElementBatchSize - 1) / nftables.ElementBatchSize
	if batches != wantBatches {
		t.Fatalf("add element batches: got %d want %d", batches, wantBatches)
	}
	if len(script) < 1000 {
		t.Fatalf("script unexpectedly small: %d bytes", len(script))
	}
	t.Logf("RU prefixes=%d compile+checks=%s render=%s script=%d bytes batches=%d",
		len(prefs), time.Since(start), renderDur, len(script), batches)
}
