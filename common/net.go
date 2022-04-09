package common

import (
	"net"
)

func UdpPortAvaliable(a net.Addr) bool {
	p, err := net.ListenPacket("udp", a.String())
	p.Close()
	return err == nil
}

func GuessDefaultIPv4() net.IP {
	conn, err := net.Dial("udp", "114.51.4.191:9810")
	if err != nil {
		return net.IPv4zero.To4()
	}
	return conn.LocalAddr().(*net.UDPAddr).IP.To4()
}

func GuessDefaultIPv6() net.IP {
	conn, err := net.Dial("udp6", "[114:514:1919::]:810")
	if err != nil {
		return net.IPv6zero
	}
	return conn.LocalAddr().(*net.UDPAddr).IP
}
