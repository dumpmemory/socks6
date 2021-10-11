package socks6

import (
	"net"
	"time"
)

type TCPConnectClient struct {
	base   net.Conn
	remote net.Addr
	rbind  net.Addr
}

func (t *TCPConnectClient) Read(b []byte) (n int, err error) {
	return t.base.Read(b)
}

func (t *TCPConnectClient) Write(b []byte) (n int, err error) {
	return t.base.Write(b)
}

func (t *TCPConnectClient) Close() error {
	return t.base.Close()
}

func (t *TCPConnectClient) LocalAddr() net.Addr {
	return t.base.LocalAddr()
}

func (t *TCPConnectClient) RemoteAddr() net.Addr {
	return t.remote
}

func (t *TCPConnectClient) ProxyBindAddr() net.Addr {
	return t.rbind
}

func (t *TCPConnectClient) ProxyRemoteAddr() net.Addr {
	return t.base.RemoteAddr()
}

func (tc *TCPConnectClient) SetDeadline(t time.Time) error {
	return tc.base.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (tc *TCPConnectClient) SetReadDeadline(t time.Time) error {
	return tc.base.SetReadDeadline(t)
}

func (tc *TCPConnectClient) SetWriteDeadline(t time.Time) error {
	return tc.base.SetWriteDeadline(t)
}
