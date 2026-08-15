package dnsproxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const maxDNSPacket = 65535

// Server is a split Direct/Exit DNS forwarder.
type Server struct {
	Listen    string
	Forwarder *Forwarder
	Log       *log.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ListenAndServe starts UDP and TCP listeners. It blocks until Shutdown or a fatal accept error.
func (s *Server) ListenAndServe() error {
	if s.Log == nil {
		s.Log = log.New(os.Stderr, "gotun-dns: ", log.LstdFlags)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	udp, err := net.ListenPacket("udp", s.Listen)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", s.Listen)
	if err != nil {
		udp.Close()
		return err
	}

	errCh := make(chan error, 2)
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		errCh <- s.serveUDP(ctx, udp)
	}()
	go func() {
		defer s.wg.Done()
		errCh <- s.serveTCP(ctx, tcp)
	}()

	err = <-errCh
	cancel()
	udp.Close()
	tcp.Close()
	s.wg.Wait()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// Shutdown stops listeners.
func (s *Server) Shutdown() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, maxDNSPacket)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go s.handlePacket(ctx, pc, addr, raw)
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handleTCP(ctx, c)
	}
}

func (s *Server) handleTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.Forwarder.Timeout + time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	l := int(lenBuf[0])<<8 | int(lenBuf[1])
	if l <= 0 || l > maxDNSPacket {
		return
	}
	raw := make([]byte, l)
	if _, err := io.ReadFull(c, raw); err != nil {
		return
	}
	out := s.processQuery(ctx, raw)
	if out == nil {
		return
	}
	lenBuf[0] = byte(len(out) >> 8)
	lenBuf[1] = byte(len(out))
	_, _ = c.Write(lenBuf[:])
	_, _ = c.Write(out)
}

type packetConnWriter interface {
	WriteTo([]byte, net.Addr) (int, error)
}

func (s *Server) handlePacket(ctx context.Context, pc packetConnWriter, addr net.Addr, raw []byte) {
	out := s.processQuery(ctx, raw)
	if out == nil {
		return
	}
	_, _ = pc.WriteTo(out, addr)
}

func (s *Server) processQuery(ctx context.Context, raw []byte) []byte {
	req := new(dns.Msg)
	req.Data = raw
	if err := req.Unpack(); err != nil {
		return nil
	}
	if len(req.Question) != 1 {
		return s.packRcode(req, dns.RcodeFormatError)
	}

	q := req.Copy()
	q.Data = nil
	resp, path, err := s.Forwarder.Forward(ctx, q)
	if err != nil {
		s.Log.Printf("path=%s query=%s forward: %v", path, req.Question[0].Header().Name, err)
		if isPerm(err) {
			s.Log.Printf("hint: Exit path needs CAP_NET_ADMIN (or CAP_NET_RAW) for SO_MARK")
		}
		return s.packRcode(req, dns.RcodeServerFailure)
	}
	if resp == nil {
		return s.packRcode(req, dns.RcodeServerFailure)
	}
	resp.ID = req.ID
	resp.Data = nil
	if err := resp.Pack(); err != nil {
		s.Log.Printf("pack reply: %v", err)
		return s.packRcode(req, dns.RcodeServerFailure)
	}
	return resp.Data
}

func (s *Server) packRcode(req *dns.Msg, rcode uint16) []byte {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Rcode = rcode
	m.Data = nil
	if err := m.Pack(); err != nil {
		return nil
	}
	return m.Data
}

func isPerm(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.EPERM {
		return true
	}
	return errors.Is(err, os.ErrPermission)
}
