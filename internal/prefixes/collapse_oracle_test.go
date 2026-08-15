package prefixes

import (
	"net/netip"
	"sort"
)

// ipv4Interval is an inclusive IPv4 address range. Used as an independent
// oracle for CollapseIPv4 union equivalence (not the CIDR stack algorithm).
type ipv4Interval struct {
	start, end uint64 // inclusive; end-start+1 fits in uint64 for any IPv4 prefix
}

func prefixToInterval(p netip.Prefix) ipv4Interval {
	p = p.Masked()
	start := uint64(ipv4ToUint32(p.Addr()))
	size := uint64(1) << (32 - p.Bits())
	return ipv4Interval{start: start, end: start + size - 1}
}

func prefixesToMergedIntervals(prefs []netip.Prefix) []ipv4Interval {
	if len(prefs) == 0 {
		return nil
	}
	intervals := make([]ipv4Interval, 0, len(prefs))
	for _, p := range prefs {
		if !p.Addr().Is4() {
			continue
		}
		intervals = append(intervals, prefixToInterval(p))
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].end < intervals[j].end
	})

	merged := []ipv4Interval{intervals[0]}
	for _, iv := range intervals[1:] {
		last := &merged[len(merged)-1]
		// Overlapping or adjacent → merge.
		if iv.start <= last.end+1 {
			if iv.end > last.end {
				last.end = iv.end
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

func intervalsEqual(a, b []ipv4Interval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func unionAddressCount(intervals []ipv4Interval) uint64 {
	var n uint64
	for _, iv := range intervals {
		n += iv.end - iv.start + 1
	}
	return n
}

func assertSameIPv4Union(t interface {
	Helper()
	Fatalf(string, ...any)
}, input, output []netip.Prefix) {
	t.Helper()
	in := prefixesToMergedIntervals(input)
	out := prefixesToMergedIntervals(output)
	if !intervalsEqual(in, out) {
		t.Fatalf("union mismatch:\n  input intervals=%v\n  output intervals=%v", in, out)
	}
	if unionAddressCount(in) != unionAddressCount(out) {
		t.Fatalf("address count mismatch: in=%d out=%d", unionAddressCount(in), unionAddressCount(out))
	}
}

func isMaximallyCollapsed(prefs []netip.Prefix) bool {
	if len(prefs) == 0 {
		return true
	}
	// Canonical order: (addr, bits).
	for i := 1; i < len(prefs); i++ {
		a, b := prefs[i-1], prefs[i]
		if a.Addr() == b.Addr() && a.Bits() == b.Bits() {
			return false // duplicate
		}
		if b.Addr().Less(a.Addr()) || (a.Addr() == b.Addr() && b.Bits() < a.Bits()) {
			return false // unsorted
		}
	}
	for i := 0; i < len(prefs); i++ {
		for j := 0; j < len(prefs); j++ {
			if i == j {
				continue
			}
			if ipv4PrefixContains(prefs[i], prefs[j]) {
				return false
			}
		}
		if i+1 < len(prefs) {
			if _, ok := mergeIPv4Siblings(prefs[i], prefs[i+1]); ok {
				return false
			}
		}
	}
	// Also check any non-adjacent sibling pair that somehow remained (should not).
	for i := 0; i < len(prefs); i++ {
		for j := i + 1; j < len(prefs); j++ {
			if _, ok := mergeIPv4Siblings(prefs[i], prefs[j]); ok {
				return false
			}
		}
	}
	return true
}
