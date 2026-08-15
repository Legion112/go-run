package prefixes

import (
	"net/netip"
	"testing"
)

func FuzzCollapseIPv4(f *testing.F) {
	f.Add([]byte{
		10, 0, 0, 0, 8,
		10, 1, 0, 0, 16,
	})
	f.Add([]byte{
		2, 60, 4, 0, 23,
		2, 60, 6, 0, 23,
	})
	f.Add([]byte{
		0, 0, 0, 0, 1,
		128, 0, 0, 0, 1,
	})
	f.Add([]byte{
		10, 0, 0, 0, 26,
		10, 0, 0, 64, 26,
		10, 0, 0, 128, 26,
		10, 0, 0, 192, 26,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		prefs := decodeFuzzPrefixes(data)
		if len(prefs) == 0 {
			return
		}
		got := CollapseIPv4(prefs)
		assertSameIPv4Union(t, prefs, got)
		twice := CollapseIPv4(got)
		assertPrefixesEqual(t, got, twice)
		if !isMaximallyCollapsed(got) {
			t.Fatalf("not maximally collapsed: %v", got)
		}
	})
}

// decodeFuzzPrefixes reads groups of 5 bytes: a.b.c.d /bits (bits clamped to 0..32).
func decodeFuzzPrefixes(data []byte) []netip.Prefix {
	const rec = 5
	n := len(data) / rec
	if n > 64 {
		n = 64 // keep fuzz cases small
	}
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		off := i * rec
		addr := netip.AddrFrom4([4]byte{data[off], data[off+1], data[off+2], data[off+3]})
		bits := int(data[off+4] % 33)
		out = append(out, netip.PrefixFrom(addr, bits).Masked())
	}
	return out
}
