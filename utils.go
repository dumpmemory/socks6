package socks6

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
)

func relayConnTuple(c, r net.Conn) string {
	return fmt.Sprintf("%s <==>> %s", conn5TupleIn(c), conn5TupleOut(r))
}

func conn3Tuple(c net.Conn) string {
	return fmt.Sprintf("%s(%s)", c.RemoteAddr().String(), connNet(c))
}

func conn5TupleIn(c net.Conn) string {
	return fmt.Sprintf("%s -(%s)-> %s", c.RemoteAddr().String(), connNet(c), c.LocalAddr().String())
}

func conn5TupleOut(c net.Conn) string {
	return fmt.Sprintf("%s -(%s)-> %s", c.LocalAddr().String(), connNet(c), c.RemoteAddr().String())
}

func connNet(c net.Conn) string {
	n := "?"
	switch c.(type) {
	case *net.TCPConn:
		n = "tcp"
	case *net.UDPConn:
		n = "udp"
	case *net.UnixConn:
		n = "unix"
	case *tls.Conn:
		n = "tls"
	case *dtls.Conn:
		n = "dtls"
	}
	return n
}

func udpPortAvaliable(a net.Addr) bool {
	p, err := net.ListenPacket("udp", a.String())
	p.Close()
	return err == nil
}
