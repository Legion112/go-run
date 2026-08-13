package sysctl

import (
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile applies desired sysctls via the Runner (proc write, then sysctl fallback).
func Reconcile(r linux.Runner, specs []policy.SysctlSpec) (int, error) {
	changes := 0
	for _, s := range specs {
		proc := "/proc/sys/" + strings.ReplaceAll(s.Key, ".", "/")
		cur, err := r.Run("bash", "-c", "cat "+proc+" 2>/dev/null || sysctl -n "+s.Key)
		if err == nil && strings.TrimSpace(cur) == s.Value {
			continue
		}
		if _, err := r.Run("bash", "-c", fmt.Sprintf("echo %s > %s", s.Value, proc)); err != nil {
			if _, err2 := r.Run("sysctl", "-w", fmt.Sprintf("%s=%s", s.Key, s.Value)); err2 != nil {
				out, rerr := r.Run("bash", "-c", "cat "+proc+" 2>/dev/null || true")
				if rerr == nil && strings.TrimSpace(out) == s.Value {
					continue
				}
				return changes, fmt.Errorf("%s: %v / %w", s.Key, err, err2)
			}
		}
		changes++
	}
	return changes, nil
}
