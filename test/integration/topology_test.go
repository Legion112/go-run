//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

const image = "gotun:lab"

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("GOTUN_INTEGRATION") == "" {
		t.Skip("set GOTUN_INTEGRATION=1 to run")
	}
}

func TestRefuseHostNetwork(t *testing.T) {
	if err := harness.RefuseHostNetwork("host"); err == nil {
		t.Fatal("expected error")
	}
	if err := harness.RefuseHostNetwork("bridge"); err != nil {
		t.Fatal(err)
	}
}

type topo struct {
	lab          *harness.Lab
	gotunPriv    string
	gotunPub     string
	exitPriv     string
	exitPub      string
	prefixesFile string
}

func setupTopo(t *testing.T) *topo {
	t.Helper()
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotun%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	// Networks (all internal bridges — never host)
	must(t, lab.CreateNetwork(ctx, "lan", "10.10.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "wgnet", "10.20.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ru", "10.200.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "foreign", "10.30.0.0/24"))

	must(t, lab.RunContainer(ctx, "client", image, "10.10.0.10", "lan", nil))
	must(t, lab.RunContainer(ctx, "gotun", image, "10.10.0.2", "lan", map[string]string{
		"wgnet": "10.20.0.2",
		"ru":    "10.200.0.2",
	}))
	must(t, lab.RunContainer(ctx, "exit", image, "10.20.0.3", "wgnet", map[string]string{
		"foreign": "10.30.0.2",
	}))
	must(t, lab.RunContainer(ctx, "ru-dest", image, "10.200.0.10", "ru", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "RU"},
	}))
	must(t, lab.RunContainer(ctx, "foreign-dest", image, "10.30.0.10", "foreign", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "FOREIGN"},
	}))

	for _, n := range []string{"client", "gotun", "exit", "ru-dest", "foreign-dest"} {
		must(t, lab.WaitReady(ctx, n))
	}

	// Generate WG keys
	gotunPriv, gotunPub := genWGKeys(t, lab, "gotun")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")

	tp := &topo{
		lab:       lab,
		gotunPriv: gotunPriv,
		gotunPub:  gotunPub,
		exitPriv:  exitPriv,
		exitPub:   exitPub,
	}

	// Destinations need default via gotun (not Docker bridge .1)
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.200.0.2"))
	must(t, lab.ExecOK(ctx, "foreign-dest", "ip", "route", "replace", "default", "via", "10.30.0.2"))

	// Configure WireGuard on exit first
	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg0 type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg0 private-key /tmp/exit.key listen-port 51820
wg set wg0 peer %s allowed-ips 10.10.0.0/24,10.99.0.0/30,10.200.0.0/24 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg0
ip link set wg0 up
ip route replace 10.10.0.0/24 dev wg0
ip route replace 10.200.0.0/24 dev wg0
# NAT foreign traffic from tunnel (ip_forward set via docker --sysctl at create)
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting oifname != "lo" masquerade || true
`, exitPriv, gotunPub)))

	// Prefixes file inside gotun
	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru.txt")
	mustWrite(t, prefPath, "10.200.0.0/24\n")
	must(t, lab.Copy(ctx, "gotun", prefPath, "/tmp/ru.txt"))

	wgConf := filepath.Join(dir, "wg0.conf")
	mustWrite(t, wgConf, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.0.1/30
ListenPort = 51820

[Peer]
PublicKey = %s
Endpoint = 10.20.0.3:51820
AllowedIPs = 10.30.0.0/24,10.99.0.0/30
PersistentKeepalive = 5
`, gotunPriv, exitPub))
	must(t, lab.Copy(ctx, "gotun", wgConf, "/tmp/wg0.conf"))

	// Apply gotun policy (tunnel up)
	must(t, lab.ExecOK(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24",
		"-wg-config", "/tmp/wg0.conf",
		"-tunnel-up", "true",
	))

	// Client: default via gotun, keep LAN on-link
	must(t, lab.ExecOK(ctx, "client", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	// Ensure client cannot reach foreign/ru except via gotun (no direct interfaces)
	// Disable IPv6 already via sysctl on container create

	tp.prefixesFile = "/tmp/ru.txt"
	return tp
}

func TestHappyPath_RUDirect_ForeignViaExit(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	ru, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil {
		t.Fatalf("RU request: %v", err)
	}
	if strings.TrimSpace(ru) != "RU" {
		t.Fatalf("want RU, got %q", ru)
	}

	// RU should not appear on wg0 counters as significant forwarded foreign — check exit did not serve RU
	// Foreign via tunnel
	foreign, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/id")
	if err != nil {
		t.Fatalf("foreign request: %v", err)
	}
	if strings.TrimSpace(foreign) != "FOREIGN" {
		t.Fatalf("want FOREIGN, got %q", foreign)
	}

	// wg0 should show transfer after foreign
	wgShow, _ := tp.lab.Exec(ctx, "gotun", "wg", "show", "wg0", "transfer")
	if strings.TrimSpace(wgShow) == "" {
		t.Fatal("expected wg transfer stats")
	}
}

func TestFailClosed_WGDownWithoutReapply(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Tear down the tunnel datapath without asking gotun to re-apply.
	// Table 100 must still terminate marked traffic (blackhole fallback).
	must(t, tp.lab.ExecOK(ctx, "gotun", "ip", "link", "set", "dev", "wg0", "down"))

	if _, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "3", "http://10.30.0.10:8080/id"); err == nil {
		t.Fatal("foreign should fail when wg0 disappears without reapply (fail-closed)")
	}
	ru, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("RU should still work: %v %q", err, ru)
	}
}

func TestFailClosed_ApplyTunnelDown(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	must(t, tp.lab.ExecOK(ctx, "gotun", "ip", "link", "set", "dev", "wg0", "down"))
	must(t, tp.lab.ExecOK(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24",
		"-wg-config", "/tmp/wg0.conf",
		"-tunnel-up", "false",
	))

	if _, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "3", "http://10.30.0.10:8080/id"); err == nil {
		t.Fatal("foreign should fail when tunnel-up=false (fail-closed)")
	}
	ru, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("RU should still work: %v %q", err, ru)
	}
}

func TestEndpointExclusion(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Ping WG endpoint underlay IP from gotun — must use underlay not wg0
	out, err := tp.lab.Exec(ctx, "gotun", "ip", "route", "get", "10.20.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "dev wg0") {
		t.Fatalf("endpoint routed via wg0 (recursive): %s", out)
	}
	_ = netip.MustParseAddr("10.20.0.3")
}

func TestIdempotentApply(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	out1, err := tp.lab.Exec(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24",
		"-wg-config", "/tmp/wg0.conf",
		"-tunnel-up", "true",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out1, "gotun apply: 0 changes") {
		t.Fatalf("second apply must report exactly 0 changes, got %q", out1)
	}
	// traffic still works
	ru, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("after re-apply RU: %v %q", err, ru)
	}
}

func TestAtomicPrefixSwapUnderTraffic(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Add second RU prefix file and re-apply while curling
	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru2.txt")
	mustWrite(t, prefPath, "10.200.0.0/24\n10.200.1.0/24\n")
	must(t, tp.lab.Copy(ctx, "gotun", prefPath, "/tmp/ru2.txt"))

	done := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 20; i++ {
			_, err = tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "2", "http://10.200.0.10:8080/id")
			if err != nil {
				done <- err
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		done <- nil
	}()

	must(t, tp.lab.ExecOK(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru2.txt",
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24",
		"-wg-config", "/tmp/wg0.conf",
		"-tunnel-up", "true",
	))

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("traffic during swap: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for traffic goroutine")
	}
}

func TestPartialFailureThenReapply(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Inject failure by applying with tunnel-up true but deleting wg mid-flight is hard;
	// instead: clear routes table and run apply with FailOn simulated via invalid device:
	// apply with tunnel-up true after renaming expectation — use apply then break routing table,
	// then successful re-apply restores.
	must(t, tp.lab.ExecOK(ctx, "gotun", "ip", "route", "flush", "table", "100"))
	must(t, tp.lab.ExecOK(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24",
		"-wg-config", "/tmp/wg0.conf",
		"-tunnel-up", "true",
	))
	foreign, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/id")
	if err != nil || strings.TrimSpace(foreign) != "FOREIGN" {
		t.Fatalf("re-apply should restore foreign path: %v %q", err, foreign)
	}
}

func TestIPv6NoBypass(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Client IPv6 disabled at container start; also gotun drops ip6
	out, _ := tp.lab.Exec(ctx, "client", "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")
	if strings.TrimSpace(out) != "1" {
		t.Fatalf("client ipv6 not disabled: %q", out)
	}
	// Attempt curl to IPv6 should fail
	if _, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "2", "http://[fd00::1]:8080/"); err == nil {
		t.Fatal("IPv6 request should not succeed")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func genWGKeys(t *testing.T, lab *harness.Lab, name string) (priv, pub string) {
	t.Helper()
	ctx := context.Background()
	priv, err := lab.Exec(ctx, name, "wg", "genkey")
	if err != nil {
		t.Fatal(err)
	}
	priv = strings.TrimSpace(priv)
	pub, err = lab.Exec(ctx, name, "bash", "-c", fmt.Sprintf("echo '%s' | wg pubkey", priv))
	if err != nil {
		t.Fatal(err)
	}
	return priv, strings.TrimSpace(pub)
}
