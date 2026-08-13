package apply_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/apply"
	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/policy"
)

func basePolicy() policy.Policy {
	return policy.Policy{
		DirectPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")},
		TunnelInterface: "wg0",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		FailMode:        policy.FailClosed,
		TunnelUp:        false, // blackhole — no need for real wg keys in unit tests
	}
}

func TestReconcile_FirstApplyMakesChanges(t *testing.T) {
	r := linux.NewRecordingRunner()
	res, err := apply.Reconcile(r, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes == 0 {
		t.Fatal("expected changes on first apply")
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "nft") {
		t.Fatalf("expected nft calls, got %v", r.Calls)
	}
	if !strings.Contains(joined, "ip rule") && !strings.Contains(joined, "rule add") {
		t.Fatalf("expected ip rule calls, got %v", r.Calls)
	}
}

func TestReconcile_SecondApplySemanticNoop(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	r.AlreadyApplied = true
	r.Calls = nil
	res, err := apply.Reconcile(r, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes != 0 {
		t.Fatalf("expected 0 semantic changes on second apply, got %d; calls=%v", res.Changes, r.Calls)
	}
}

func TestReconcile_PartialFailureStops(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "ip route"
	_, err := apply.Reconcile(r, basePolicy())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "routing") {
		t.Fatalf("want routing error, got %v", err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "nft") {
		t.Fatalf("expected nft before failure, calls=%v", r.Calls)
	}
}

func TestSwapSetElements_UsesTransaction(t *testing.T) {
	r := linux.NewRecordingRunner()
	_, err := nftables.SwapSetElements(r, "inet", "gotun", "ru_nets", []string{"10.200.0.0/24", "10.200.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "flush set") || !strings.Contains(joined, "<<STDIN>>") {
		t.Fatalf("expected atomic nft -f transaction, got %v", r.Calls)
	}
}

func TestCompileIncludesEndpointInNftScript(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range r.Calls {
		if strings.Contains(c, "<<STDIN>>") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected nft -f with stdin script")
	}
}
