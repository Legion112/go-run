package wireguard

import (
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile brings up a managed WireGuard interface from declarative spec.
func Reconcile(r linux.Runner, spec policy.WireGuardSpec) (int, error) {
	if !spec.Managed {
		return 0, nil
	}
	changes := 0
	iface := spec.Interface

	link, err := r.Run("ip", "link", "show", "dev", iface)
	missing := err != nil || link == "" || strings.Contains(link, "does not exist") || strings.Contains(link, "Cannot find")
	if missing {
		if _, err := r.Run("ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			return changes, err
		}
		changes++
	}

	if !spec.Up {
		// Fail-closed: remove AllowedIPs routes and bring interface down.
		for _, p := range spec.Peer.AllowedIPs {
			if p.IsValid() {
				_, _ = r.Run("ip", "route", "del", p.String(), "dev", iface)
			}
		}
		if _, err := r.Run("ip", "link", "set", "dev", iface, "down"); err != nil {
			return changes, err
		}
		changes++
		return changes, nil
	}

	// If interface already up and peer configured, treat as semantic match for idempotency.
	wgOut, _ := r.Run("wg", "show", iface)
	if !missing && strings.Contains(wgOut, spec.Peer.PublicKey) && strings.Contains(link, "UP") {
		return changes, nil
	}

	args := []string{"set", iface, "private-key", "/dev/stdin"}
	if spec.ListenPort > 0 {
		args = append(args, "listen-port", fmt.Sprintf("%d", spec.ListenPort))
	}
	if _, err := r.RunWithInput("wg", spec.PrivateKey+"\n", args...); err != nil {
		return changes, err
	}
	changes++

	peer := spec.Peer
	if peer.PublicKey != "" {
		pargs := []string{"set", iface, "peer", peer.PublicKey}
		if peer.Endpoint != "" {
			pargs = append(pargs, "endpoint", peer.Endpoint)
		}
		if len(peer.AllowedIPs) > 0 {
			var ips []string
			for _, p := range peer.AllowedIPs {
				ips = append(ips, p.String())
			}
			pargs = append(pargs, "allowed-ips", strings.Join(ips, ","))
		}
		if peer.PersistentKeepalive > 0 {
			pargs = append(pargs, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKeepalive))
		}
		if _, err := r.Run("wg", pargs...); err != nil {
			return changes, err
		}
		changes++
	}

	if spec.Address.IsValid() {
		if _, err := r.Run("ip", "address", "replace", spec.Address.String(), "dev", iface); err != nil {
			return changes, err
		}
		changes++
	}
	if _, err := r.Run("ip", "link", "set", "dev", iface, "up"); err != nil {
		return changes, err
	}
	changes++

	// Ensure AllowedIPs appear as routes (some environments suppress WG auto-routes).
	for _, p := range spec.Peer.AllowedIPs {
		if !p.IsValid() {
			continue
		}
		if _, err := r.Run("ip", "route", "replace", p.String(), "dev", iface); err != nil {
			return changes, err
		}
		changes++
	}
	return changes, nil
}

// SetDown brings the interface down (for fail-closed tests).
func SetDown(r linux.Runner, iface string) error {
	_, err := r.Run("ip", "link", "set", "dev", iface, "down")
	return err
}

// Clear deletes the WireGuard interface.
func Clear(r linux.Runner, iface string) error {
	_, err := r.Run("ip", "link", "del", "dev", iface)
	if err != nil && strings.Contains(err.Error(), "Cannot find") {
		return nil
	}
	return err
}
