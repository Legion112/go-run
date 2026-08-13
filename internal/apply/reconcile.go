package apply

import (
	"fmt"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/linux/routing"
	"github.com/legion/go-tun/internal/linux/sysctl"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/wireguard"
)

// Result summarizes a reconcile.
type Result struct {
	Changes int
	State   policy.DesiredKernelState
}

// Reconcile applies Policy to the kernel via DesiredKernelState.
// Order: sysctl → nft → wireguard → ip rules/routes
// (WireGuard before routes so table 100 can reference wg0).
// On mid-way failure, returns error without rolling back prior subsystems.
func Reconcile(r linux.Runner, p policy.Policy) (Result, error) {
	st, err := policy.Compile(p)
	if err != nil {
		return Result{}, err
	}
	total := 0

	c, err := sysctl.Reconcile(r, st.Sysctls)
	total += c
	if err != nil {
		return Result{Changes: total, State: st}, fmt.Errorf("sysctl: %w", err)
	}

	c, err = nftables.Reconcile(r, st.Nft)
	total += c
	if err != nil {
		return Result{Changes: total, State: st}, fmt.Errorf("nftables: %w", err)
	}

	c, err = wireguard.Reconcile(r, st.WireGuard)
	total += c
	if err != nil {
		return Result{Changes: total, State: st}, fmt.Errorf("wireguard: %w", err)
	}

	c, err = wireguard.Reconcile(r, st.WireGuardClients)
	total += c
	if err != nil {
		return Result{Changes: total, State: st}, fmt.Errorf("wireguard-clients: %w", err)
	}

	c, err = routing.Reconcile(r, st.IPRules, st.Routes)
	total += c
	if err != nil {
		return Result{Changes: total, State: st}, fmt.Errorf("routing: %w", err)
	}

	return Result{Changes: total, State: st}, nil
}

// Clear removes gotun-owned kernel objects.
func Clear(r linux.Runner) error {
	_ = wireguard.Clear(r, policy.DefaultTunnelIface)
	_ = wireguard.Clear(r, policy.DefaultClientsIface)
	_ = routing.Clear(r, policy.DefaultRulePriority, policy.DefaultTableID)
	_ = nftables.Clear(r, policy.OwnedNftFamily, policy.OwnedNftTable)
	return nil
}
