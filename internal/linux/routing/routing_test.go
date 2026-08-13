package routing

import (
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func TestTableRoutesMatch_Exact(t *testing.T) {
	want := []policy.RouteSpec{
		{Table: 100, Device: "wg0", Metric: policy.TunnelRouteMetric},
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "default dev wg0 metric 10 \nblackhole default metric 100\n"
	if !tableRoutesMatch(out, want) {
		t.Fatal("expected exact dual-route match")
	}
}

func TestTableRoutesMatch_StaleDeviceRejected(t *testing.T) {
	// Desired is blackhole-only (tunnel down), but a stale low-metric device route remains.
	want := []policy.RouteSpec{
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "default dev wg0 metric 10\nblackhole default metric 100\n"
	if tableRoutesMatch(out, want) {
		t.Fatal("stale device route must make table mismatch")
	}
}

func TestTableRoutesMatch_SubsetNotEnough(t *testing.T) {
	want := []policy.RouteSpec{
		{Table: 100, Device: "wg0", Metric: policy.TunnelRouteMetric},
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "blackhole default metric 100\n"
	if tableRoutesMatch(out, want) {
		t.Fatal("missing device route must mismatch")
	}
}
