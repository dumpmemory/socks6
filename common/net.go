package common

import (
	"net"

	"github.com/studentmain/socks6/internal"
)

func UdpPortAvaliable(a net.Addr) bool {
	p, err := net.ListenPacket("udp", a.String())
	p.Close()
	return err == nil
}

func GuessDefaultIPv4() net.IP {
	conn := internal.Must2(net.Dial("udp", "114.51.4.191:9810")).(*net.UDPConn)
	return conn.LocalAddr().(*net.UDPAddr).IP.To4()
}

func GuessDefaultIPv6() net.IP {
	conn := internal.Must2(net.Dial("udp", "[114:514:1919::]:810")).(*net.UDPConn)
	return conn.LocalAddr().(*net.UDPAddr).IP
}
