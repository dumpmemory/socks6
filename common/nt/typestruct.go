package nt

import (
	"context"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/studentmain/socks6/common/arrayx"
	"github.com/studentmain/socks6/internal"
)

// net.Conn is a good abstraction for net stream

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

func ReadUDPDatagram(pc net.PacketConn) (Datagram, error) {
	b := make([]byte, 4096)
	n, addr, err := pc.ReadFrom(b)
	if err != nil {
		return nil, err
	}
	return udpDatagram{
		raddr: addr,
		data:  b[:n],
		conn:  pc,
	}, nil
}

type netConnSeqPacket struct {
	conn net.Conn
	netCommon
}

var _ SeqPacket = netConnSeqPacket{}

func (u netConnSeqPacket) NextDatagram() (Datagram, error) {
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	n, err := u.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	dgram := dtlsDatagram{
		data: arrayx.Dup(buf[:n]),
		conn: u.conn,
	}
	return dgram, nil
}
func (u netConnSeqPacket) Reply(b []byte) error {
	_, err := u.conn.Write(b)
	return err
}

func WrapNetConnUDP(conn net.Conn) SeqPacket {
	return netConnSeqPacket{conn: conn, netCommon: conn}
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

type quicMuxConn struct {
	conn quic.Connection
}

var _ MultiplexedConn = quicMuxConn{}
var _ SeqPacket = quicMuxConn{}

func (u quicMuxConn) Accept() (net.Conn, error) {
	qs, err := u.conn.AcceptStream(context.Background())
	return quicConn{Connection: u.conn, Stream: qs}, err
}

func (u quicMuxConn) Dial() (net.Conn, error) {
	qs, err := u.conn.OpenStream()
	return quicConn{Connection: u.conn, Stream: qs}, err
}

func (u quicMuxConn) Close() error {
	// noop
	return nil
}

func (u quicMuxConn) NextDatagram() (Datagram, error) {
	data, err := u.conn.ReceiveMessage()
	if err != nil {
		return nil, err
	}

	dgram := quicDatagram{
		data: data,
		conn: u.conn,
	}
	return dgram, nil
}
func (u quicMuxConn) Reply(b []byte) error {
	return u.conn.SendMessage(b)
}
func (u quicMuxConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u quicMuxConn) RemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}

func (u quicMuxConn) SetDeadline(t time.Time) error {
	return nil
}

func (u quicMuxConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (u quicMuxConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func WrapQUICConn(conn quic.Connection) DualModeMultiplexedConn {
	return quicMuxConn{conn: conn}
}

type quicConn struct {
	quic.Stream
	quic.Connection
}

var _ net.Conn = quicConn{}

type quicDatagram struct {
	data []byte
	conn quic.Connection
}

var _ Datagram = quicDatagram{}

func (u quicDatagram) Data() []byte {
	return u.data
}
func (u quicDatagram) Reply(b []byte) error {
	return u.conn.SendMessage(b)
}
func (u quicDatagram) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u quicDatagram) RemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}
