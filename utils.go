package socks6

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/internal"
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

func guessDefaultIP4() net.IP {
	conn := internal.Must2(net.Dial("udp", "114.51.4.191:9810")).(*net.UDPConn)
	return conn.LocalAddr().(*net.UDPAddr).IP.To4()
}

func guessDefaultIP6() net.IP {
	conn := internal.Must2(net.Dial("udp", "[114:514:1919::]:810")).(*net.UDPConn)
	return conn.LocalAddr().(*net.UDPAddr).IP
}
