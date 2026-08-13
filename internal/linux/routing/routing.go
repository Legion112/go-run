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

	byTable := map[int][]policy.RouteSpec{}
	for _, rt := range routes {
		byTable[rt.Table] = append(byTable[rt.Table], rt)
	}
	for table, want := range byTable {
		out, _ := r.Run("ip", "route", "show", "table", fmt.Sprintf("%d", table))
		if tableRoutesMatch(out, want) {
			continue
		}
		_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", table))
		for _, rt := range want {
			if err := addRoute(r, rt); err != nil {
				return changes, err
			}
		}
		changes++
	}
	return changes, nil
}

func tableRoutesMatch(out string, want []policy.RouteSpec) bool {
	for _, rt := range want {
		if !routePresent(out, rt) {
			return false
		}
	}
	return true
}

func routePresent(out string, rt policy.RouteSpec) bool {
	if rt.Blackhole {
		if !strings.Contains(out, "blackhole") && !strings.Contains(out, "unreachable") {
			return false
		}
		if rt.Metric > 0 && !strings.Contains(out, fmt.Sprintf("metric %d", rt.Metric)) {
			return false
		}
		return true
	}
	if rt.Device == "" || !strings.Contains(out, "dev "+rt.Device) {
		return false
	}
	if rt.Metric > 0 && !strings.Contains(out, fmt.Sprintf("metric %d", rt.Metric)) {
		return false
	}
	return true
}

func addRoute(r linux.Runner, rt policy.RouteSpec) error {
	table := fmt.Sprintf("%d", rt.Table)
	if rt.Blackhole {
		args := []string{"route", "replace", "blackhole", "default", "table", table}
		if rt.Metric > 0 {
			args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
		}
		_, err := r.Run("ip", args...)
		return err
	}
	args := []string{"route", "replace", "default", "dev", rt.Device, "table", table}
	if rt.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
	}
	_, err := r.Run("ip", args...)
	return err
}

// Clear removes owned rules and flushes the routing table.
func Clear(r linux.Runner, priority, table int) error {
	_, _ = r.Run("ip", "rule", "del", "priority", fmt.Sprintf("%d", priority))
	_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", table))
	return nil
}
