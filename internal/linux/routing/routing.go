package routing

import (
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile applies owned ip rules and routes. Returns changes count.
func Reconcile(r linux.Runner, rules []policy.IPRuleSpec, routes []policy.RouteSpec) (int, error) {
	changes := 0

	for _, rule := range rules {
		out, _ := r.Run("ip", "rule", "show")
		want := fmt.Sprintf("%d:", rule.Priority)
		markTok := fmt.Sprintf("fwmark 0x%x", rule.Mark)
		tableTok := fmt.Sprintf("lookup %d", rule.Table)
		if strings.Contains(out, want) && strings.Contains(out, markTok) && strings.Contains(out, tableTok) {
			continue
		}
		// delete any existing at priority then add
		_, _ = r.Run("ip", "rule", "del", "priority", fmt.Sprintf("%d", rule.Priority))
		if _, err := r.Run("ip", "rule", "add", "priority", fmt.Sprintf("%d", rule.Priority),
			"fwmark", fmt.Sprintf("0x%x", rule.Mark), "lookup", fmt.Sprintf("%d", rule.Table)); err != nil {
			return changes, err
		}
		changes++
	}

	for _, rt := range routes {
		out, _ := r.Run("ip", "route", "show", "table", fmt.Sprintf("%d", rt.Table))
		if rt.Blackhole {
			if strings.Contains(out, "blackhole") || strings.Contains(out, "unreachable") {
				continue
			}
			_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", rt.Table))
			if _, err := r.Run("ip", "route", "replace", "blackhole", "default", "table", fmt.Sprintf("%d", rt.Table)); err != nil {
				return changes, err
			}
			changes++
			continue
		}
		if rt.Device != "" && strings.Contains(out, "dev "+rt.Device) {
			continue
		}
		_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", rt.Table))
		if _, err := r.Run("ip", "route", "replace", "default", "dev", rt.Device, "table", fmt.Sprintf("%d", rt.Table)); err != nil {
			return changes, err
		}
		changes++
	}
	return changes, nil
}

// Clear removes owned rules and flushes the routing table.
func Clear(r linux.Runner, priority, table int) error {
	_, _ = r.Run("ip", "rule", "del", "priority", fmt.Sprintf("%d", priority))
	_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", table))
	return nil
}
