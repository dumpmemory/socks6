package nt

import (
	"net"
	"time"
)

// NetBufferOnlyReader is a wrapper over net.Conn
// which try to only read data which already in OS buffer
// by setting read timeout to 1us
type NetBufferOnlyReader struct {
	Conn net.Conn
}

func (n *NetBufferOnlyReader) Read(b []byte) (int, error) {
	if err := n.Conn.SetReadDeadline(time.Now().Add(1 * time.Microsecond)); err != nil {
		return 0, err
	}

	c, err := n.Conn.Read(b)
	if err != nil {
		return 0, err
	}

	if err := n.Conn.SetReadDeadline(time.Time{}); err != nil {
		return 0, err
	}
	return c, nil
}
