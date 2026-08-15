package prefixes

import (
	"fmt"
	"net/netip"
	"sort"
)

// CollapseIPv4 returns the minimal set of IPv4 prefixes covering exactly the same
// IPv4 addresses as prefs. Prefs must be IPv4-only; an IPv6 prefix panics.
//
// Steps: canonicalize, dedupe, remove covered prefixes, then merge sibling pairs
// with a stack until no further lossless merge is possible.
func CollapseIPv4(prefs []netip.Prefix) []netip.Prefix {
	if len(prefs) == 0 {
		return nil
	}

	normalized := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if !p.Addr().Is4() {
			panic(fmt.Sprintf("prefixes.CollapseIPv4: IPv6 prefix %s not supported", p))
		}
		normalized = append(normalized, p.Masked())
	}

	sort.Slice(normalized, func(i, j int) bool {
		ai, aj := normalized[i], normalized[j]
		if ai.Addr() != aj.Addr() {
			return ai.Addr().Less(aj.Addr())
		}
		return ai.Bits() < aj.Bits()
	})

	// Deduplicate.
	deduped := normalized[:0]
	for _, p := range normalized {
		if len(deduped) > 0 && deduped[len(deduped)-1] == p {
			continue
		}
		deduped = append(deduped, p)
	}

	uncovered := removeCoveredIPv4(deduped)
	return mergeSiblingStack(uncovered)
}

func removeCoveredIPv4(prefs []netip.Prefix) []netip.Prefix {
	// prefs sorted by (addr, bits ascending) — broader prefixes come first for same addr.
	out := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		covered := false
		for _, k := range out {
			if ipv4PrefixContains(k, p) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// ipv4PrefixContains reports whether outer fully contains inner (both IPv4, masked).
func ipv4PrefixContains(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return netip.PrefixFrom(inner.Addr(), outer.Bits()).Masked() == outer
}

func mergeSiblingStack(prefs []netip.Prefix) []netip.Prefix {
	stack := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		stack = append(stack, p)
		for len(stack) >= 2 {
			a, b := stack[len(stack)-2], stack[len(stack)-1]
			parent, ok := mergeIPv4Siblings(a, b)
			if !ok {
				break
			}
			stack = stack[:len(stack)-2]
			stack = append(stack, parent)
		}
	}
	return stack
}

// mergeIPv4Siblings returns the parent prefix if a and b are exact halves of it.
func mergeIPv4Siblings(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return netip.Prefix{}, false
	}
	if b.Addr().Less(a.Addr()) {
		a, b = b, a
	}
	parentBits := a.Bits() - 1
	parent := netip.PrefixFrom(a.Addr(), parentBits).Masked()
	if netip.PrefixFrom(b.Addr(), parentBits).Masked() != parent {
		return netip.Prefix{}, false
	}

	left := netip.PrefixFrom(parent.Addr(), a.Bits()).Masked()
	if a != left {
		return netip.Prefix{}, false
	}

	half := uint32(1) << (32 - a.Bits())
	rightStart := ipv4ToUint32(parent.Addr()) + half
	right := netip.PrefixFrom(uint32ToIPv4(rightStart), a.Bits()).Masked()
	if b != right {
		return netip.Prefix{}, false
	}
	return parent, true
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIPv4(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	})
}
