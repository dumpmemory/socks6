package socks6

import (
	"net"

	"github.com/studentmain/socks6/internal"
)

// net.Conn is a good abstraction for net stream

type Datagram interface {
	Data() []byte
	Reply(b []byte) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type udpDatagram struct {
	data  []byte
	conn  net.PacketConn
	raddr net.Addr
}

var _ Datagram = udpDatagram{}

func (u udpDatagram) Data() []byte {
	return u.data
}
func (u udpDatagram) Reply(b []byte) error {
	_, err := u.conn.WriteTo(b, u.raddr)
	return err
}
func (u udpDatagram) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u udpDatagram) RemoteAddr() net.Addr {
	return u.raddr
}

type SeqPacket interface {
	NextDatagram() (Datagram, error)
	Reply(b []byte) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type dtlsSeqPacket struct {
	conn net.Conn
}

var _ SeqPacket = dtlsSeqPacket{}

func (u dtlsSeqPacket) NextDatagram() (Datagram, error) {
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	n, err := u.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	dgram := dtlsDatagram{
		data: internal.Dup(buf[:n]),
		conn: u.conn,
	}
	return dgram, nil
}
func (u dtlsSeqPacket) Reply(b []byte) error {
	_, err := u.conn.Write(b)
	return err
}
func (u dtlsSeqPacket) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u dtlsSeqPacket) RemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}

type dtlsDatagram struct {
	data []byte
	conn net.Conn
}

var _ Datagram = dtlsDatagram{}

func (u dtlsDatagram) Data() []byte {
	return u.data
}
func (u dtlsDatagram) Reply(b []byte) error {
	_, err := u.conn.Write(b)
	return err
}
func (u dtlsDatagram) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u dtlsDatagram) RemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}
