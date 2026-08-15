//go:build !linux

package dnsproxy

import (
	"fmt"
	"net"
)

func applySOMark(d *net.Dialer, mark uint32) error {
	return fmt.Errorf("SO_MARK 0x%x is only supported on Linux", mark)
}
