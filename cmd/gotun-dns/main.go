package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/dnsproxy"
	"github.com/legion/go-tun/internal/policy"
)

func main() {
	listen := flag.String("listen", ":53", "UDP/TCP listen address")
	directUp := flag.String("direct-upstream", "77.88.8.8:53", "upstream for Direct path (.ru); unmarked dial")
	exitUp := flag.String("exit-upstream", "1.1.1.1:53", "upstream for Exit path; dialed with SO_MARK")
	markStr := flag.String("mark", fmt.Sprintf("0x%x", policy.DefaultMark), "SO_MARK for Exit path (must match gotun apply)")
	timeout := flag.Duration("timeout", 3*time.Second, "upstream query timeout")
	flag.Parse()

	mark, err := parseMark(*markStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotun-dns: mark: %v\n", err)
		os.Exit(2)
	}

	fwd, err := dnsproxy.NewForwarder(
		dnsproxy.DefaultRUClassifier(),
		dnsproxy.Upstream{Direct: *directUp, Exit: *exitUp},
		dnsproxy.DialConfig{Timeout: *timeout, Mark: mark},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotun-dns: %v\n", err)
		os.Exit(1)
	}

	log.Printf("gotun-dns listen=%s direct-upstream=%s exit-upstream=%s mark=0x%x",
		*listen, *directUp, *exitUp, mark)
	log.Printf("gotun-dns requires CAP_NET_BIND_SERVICE for :53 (if non-root) and CAP_NET_ADMIN (or CAP_NET_RAW) for SO_MARK")

	srv := &dnsproxy.Server{Listen: *listen, Forwarder: fwd}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func parseMark(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}
