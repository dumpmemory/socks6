package nt

import (
	"net"
)

// net.Conn is a good abstraction for net stream

type Datagram interface {
	Data() []byte
	Reply(b []byte) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type SeqPacket interface {
	NextDatagram() (Datagram, error)
	Reply(b []byte) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type MultiplexedConn interface {
	Accept() (net.Conn, error)
	Dial() (net.Conn, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}
