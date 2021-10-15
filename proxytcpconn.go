package socks6

import (
	"net"
)

// netConn is net.Conn, but private
type netConn net.Conn

type addrPair struct {
	local  net.Addr
	remote net.Addr
}

// ProxyTCPConn represents a proxied TCP connection, implements net.Conn
type ProxyTCPConn struct {
	netConn
	addrPair
}

// [localaddr]----netConn----[[proxyremoteaddr][proxylocaladdr]]----[remoteaddr]

func (t *ProxyTCPConn) RemoteAddr() net.Addr {
	return t.remote
}

func (t *ProxyTCPConn) ProxyLocalAddr() net.Addr {
	return t.addrPair.local
}

func (t *ProxyTCPConn) ProxyRemoteAddr() net.Addr {
	return t.addrPair.remote
}
