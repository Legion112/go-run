//go:build integration

package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestDNSSplit_GeoEgressIdentity proves gotun-dns sends .ru Direct (unmarked)
// and other names Exit (SO_MARK → wg-exit). labdns answers depend on source IP.
func TestDNSSplit_GeoEgressIdentity(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	labdnsCmd := `labdns -listen :53 -map 10.200.0.0/24=10.200.0.50 -map 10.30.0.0/24=10.30.0.50 >/tmp/labdns.log 2>&1 &`
	must(t, tp.lab.ExecOK(ctx, "ru-dest", "bash", "-c", labdnsCmd))
	must(t, tp.lab.ExecOK(ctx, "foreign-dest", "bash", "-c", labdnsCmd))
	time.Sleep(300 * time.Millisecond)

	must(t, tp.lab.ExecOK(ctx, "gotun", "bash", "-c",
		`gotun-dns -listen 10.10.0.2:53 -direct-upstream 10.200.0.10:53 -exit-upstream 10.30.0.10:53 -mark 0x1 >/tmp/gotun-dns.log 2>&1 &`))
	time.Sleep(300 * time.Millisecond)

	ruAns, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=3", "+tries=1", "@10.10.0.2", "lavka.yandex.ru", "A")
	if err != nil {
		dumpDNSLogs(t, tp)
		t.Fatalf("dig .ru: %v", err)
	}
	if got := strings.TrimSpace(ruAns); got != "10.200.0.50" {
		dumpDNSLogs(t, tp)
		t.Fatalf("want RU geo A 10.200.0.50, got %q", got)
	}

	exAns, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=3", "+tries=1", "@10.10.0.2", "example.com", "A")
	if err != nil {
		dumpDNSLogs(t, tp)
		t.Fatalf("dig example.com: %v", err)
	}
	if got := strings.TrimSpace(exAns); got != "10.30.0.50" {
		dumpDNSLogs(t, tp)
		t.Fatalf("want foreign geo A 10.30.0.50, got %q", got)
	}

	norm, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=3", "+tries=1", "@10.10.0.2", "YANDEX.RU", "A")
	if err != nil || strings.TrimSpace(norm) != "10.200.0.50" {
		t.Fatalf("YANDEX.RU normalize: %v %q", err, norm)
	}

	must(t, tp.lab.ExecOK(ctx, "gotun", "ip", "link", "set", "dev", "wg-exit", "down"))
	time.Sleep(200 * time.Millisecond)

	ru2, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=2", "+tries=1", "@10.10.0.2", "mail.ru", "A")
	if err != nil || strings.TrimSpace(ru2) != "10.200.0.50" {
		t.Fatalf(".ru should work with wg-exit down: %v %q", err, ru2)
	}
	ex2, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=2", "+tries=1", "@10.10.0.2", "example.org", "A")
	if err == nil && strings.TrimSpace(ex2) == "10.30.0.50" {
		t.Fatalf("non-.ru should not get foreign answer with wg-exit down, got %q", ex2)
	}
}

func dumpDNSLogs(t *testing.T, tp *topo) {
	t.Helper()
	ctx := context.Background()
	for _, pair := range [][2]string{
		{"gotun", "/tmp/gotun-dns.log"},
		{"ru-dest", "/tmp/labdns.log"},
		{"foreign-dest", "/tmp/labdns.log"},
	} {
		out, _ := tp.lab.Exec(ctx, pair[0], "cat", pair[1])
		t.Logf("%s %s:\n%s", pair[0], pair[1], out)
	}
}
