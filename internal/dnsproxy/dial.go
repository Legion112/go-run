package dnsproxy

import (
	"fmt"
	"net"
	"time"
)

// DialConfig configures upstream dialers for Direct and Exit paths.
type DialConfig struct {
	Timeout time.Duration
	// Mark is applied via SO_MARK on the Exit path (Linux). Zero means unmarked Exit dial (tests).
	Mark uint32
}

// NewDirectDialer returns an unmarked dialer for the Direct path.
func NewDirectDialer(cfg DialConfig) *net.Dialer {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &net.Dialer{Timeout: timeout}
}

// NewExitDialer returns a dialer for the Exit path (SO_MARK on Linux when Mark != 0).
func NewExitDialer(cfg DialConfig) (*net.Dialer, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	if cfg.Mark == 0 {
		return d, nil
	}
	if err := applySOMark(d, cfg.Mark); err != nil {
		return nil, err
	}
	return d, nil
}

func markEPERMHint(mark uint32, err error) error {
	return fmt.Errorf("SO_MARK 0x%x: %w (need CAP_NET_ADMIN or CAP_NET_RAW; Direct path may still work)", mark, err)
}
