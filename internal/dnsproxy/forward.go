package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// Upstream holds the Direct and Exit resolver addresses (host:port).
type Upstream struct {
	Direct string
	Exit   string
}

// Exchanger abstracts dns.Client for tests.
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, network, address string) (*dns.Msg, time.Duration, error)
}

// ClientExchanger wraps dns.Client with a fixed dialer/transport.
type ClientExchanger struct {
	Client *dns.Client
}

func (c ClientExchanger) Exchange(ctx context.Context, m *dns.Msg, network, address string) (*dns.Msg, time.Duration, error) {
	return c.Client.Exchange(ctx, m, network, address)
}

// Forwarder classifies and forwards DNS queries with UDP then TC→TCP retry.
type Forwarder struct {
	Classifier Classifier
	Upstream   Upstream
	Timeout    time.Duration

	DirectEx Exchanger
	ExitEx   Exchanger
}

// NewForwarder builds a Forwarder with Direct (unmarked) and Exit (marked) clients.
func NewForwarder(c Classifier, up Upstream, dial DialConfig) (*Forwarder, error) {
	directDial := NewDirectDialer(dial)
	exitDial, err := NewExitDialer(dial)
	if err != nil {
		return nil, err
	}
	timeout := dial.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Forwarder{
		Classifier: c,
		Upstream:   up,
		Timeout:    timeout,
		DirectEx:   ClientExchanger{Client: newClient(directDial, timeout)},
		ExitEx:     ClientExchanger{Client: newClient(exitDial, timeout)},
	}, nil
}

func newClient(d *net.Dialer, timeout time.Duration) *dns.Client {
	t := dns.NewTransport()
	t.Dialer = d
	t.ReadTimeout = timeout
	t.WriteTimeout = timeout
	return &dns.Client{Transport: t}
}

// Forward sends m to the classified upstream. On UDP truncation, retries TCP
// with the same path dialer. m should be a packed or packable query copy.
func (f *Forwarder) Forward(ctx context.Context, m *dns.Msg) (*dns.Msg, Path, error) {
	if len(m.Question) != 1 {
		return nil, PathExit, fmt.Errorf("expected exactly one question, got %d", len(m.Question))
	}
	name := m.Question[0].Header().Name
	path := f.Classifier.Classify(name)
	addr := f.Upstream.Direct
	ex := f.DirectEx
	if path == PathExit {
		addr = f.Upstream.Exit
		ex = f.ExitEx
	}
	if addr == "" {
		return nil, path, fmt.Errorf("empty upstream for path %s", path)
	}

	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()

	// Ensure re-pack on each attempt when Data may be stale after mutation.
	m.Data = nil
	r, _, err := ex.Exchange(ctx, m, "udp", addr)
	if r != nil && r.Truncated {
		m.Data = nil
		tcpCtx, tcpCancel := context.WithTimeout(context.WithoutCancel(ctx), f.Timeout)
		defer tcpCancel()
		tr, _, terr := ex.Exchange(tcpCtx, m, "tcp", addr)
		if terr != nil {
			return tr, path, terr
		}
		return tr, path, nil
	}
	if err != nil {
		return r, path, err
	}
	return r, path, nil
}
