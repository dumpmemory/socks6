package nt

import (
	"net"
	"time"
)

// net.Conn is a good abstraction for net stream

type addrPair interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type setDeadline interface {
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type netCommon interface {
	Close() error
	setDeadline
	addrPair
}

type Datagram interface {
	Data() []byte
	Reply(b []byte) error
	addrPair
}

type SeqPacket interface {
	NextDatagram() (Datagram, error)
	Reply(b []byte) error
	netCommon
}

type MultiplexedConn interface {
	Accept() (net.Conn, error)
	Dial() (net.Conn, error)
	netCommon
}

type DualModeMultiplexedConn interface {
	MultiplexedConn
	SeqPacket
}
