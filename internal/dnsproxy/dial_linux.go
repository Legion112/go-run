package dnsproxy

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func applySOMark(d *net.Dialer, mark uint32) error {
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return markEPERMHint(mark, sockErr)
		}
		return nil
	}
	return nil
}
