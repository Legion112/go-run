package dnsproxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

type recordingExchanger struct {
	mu       sync.Mutex
	calls    []string // "udp"|"tcp"
	udpReply *dns.Msg
	tcpReply *dns.Msg
	udpErr   error
	tcpErr   error
}

func (r *recordingExchanger) Exchange(_ context.Context, m *dns.Msg, network, _ string) (*dns.Msg, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, network)
	if network == "tcp" {
		return r.tcpReply, 0, r.tcpErr
	}
	return r.udpReply, 0, r.udpErr
}

func TestExitUDPTruncatedFallsBackToMarkedTCP(t *testing.T) {
	q := dns.NewMsg("example.com.", dns.TypeA)
	udp := new(dns.Msg)
	udp.Response = true
	udp.Truncated = true
	udp.Question = q.Question
	tcp := new(dns.Msg)
	tcp.Response = true
	tcp.Question = q.Question

	rec := &recordingExchanger{udpReply: udp, tcpReply: tcp}
	f := &Forwarder{
		Classifier: DefaultRUClassifier(),
		Upstream:   Upstream{Direct: "127.0.0.1:53", Exit: "127.0.0.1:53"},
		Timeout:    time.Second,
		DirectEx:   &recordingExchanger{},
		ExitEx:     rec,
	}
	got, path, err := f.Forward(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if path != PathExit {
		t.Fatalf("path=%s", path)
	}
	if got == nil || got.Truncated {
		t.Fatalf("want full TCP reply, got %+v", got)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 2 || rec.calls[0] != "udp" || rec.calls[1] != "tcp" {
		t.Fatalf("calls=%v", rec.calls)
	}
}

func TestDirectUDPTruncatedFallsBackToUnmarkedTCP(t *testing.T) {
	q := dns.NewMsg("yandex.ru.", dns.TypeA)
	udp := new(dns.Msg)
	udp.Response = true
	udp.Truncated = true
	udp.Question = q.Question
	tcp := new(dns.Msg)
	tcp.Response = true
	tcp.Question = q.Question

	direct := &recordingExchanger{udpReply: udp, tcpReply: tcp}
	exit := &recordingExchanger{}
	f := &Forwarder{
		Classifier: DefaultRUClassifier(),
		Upstream:   Upstream{Direct: "10.0.0.1:53", Exit: "10.0.0.2:53"},
		Timeout:    time.Second,
		DirectEx:   direct,
		ExitEx:     exit,
	}
	got, path, err := f.Forward(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if path != PathDirect {
		t.Fatalf("path=%s", path)
	}
	if got == nil || got.Truncated {
		t.Fatal("want TCP reply")
	}
	direct.mu.Lock()
	defer direct.mu.Unlock()
	if len(direct.calls) != 2 || direct.calls[0] != "udp" || direct.calls[1] != "tcp" {
		t.Fatalf("direct calls=%v", direct.calls)
	}
	exit.mu.Lock()
	defer exit.mu.Unlock()
	if len(exit.calls) != 0 {
		t.Fatalf("exit should not be used: %v", exit.calls)
	}
}

func TestForwardRejectsMultiQuestion(t *testing.T) {
	m := new(dns.Msg)
	m.Question = []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "a.example.", Class: dns.ClassINET}},
		&dns.A{Hdr: dns.Header{Name: "b.example.", Class: dns.ClassINET}},
	}
	f := &Forwarder{Classifier: DefaultRUClassifier(), Timeout: time.Second}
	_, _, err := f.Forward(context.Background(), m)
	if err == nil {
		t.Fatal("expected error")
	}
}
