package socks6

import (
	"context"
	"net"
	"time"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/lg"
	"github.com/studentmain/socks6/message"
)

type UDPDownlink func(b []byte) error

type ClientPacket struct {
	Message  *message.UDPHeader
	Source   net.Addr
	Downlink UDPDownlink
}

type udpAssociation struct {
	id  uint64
	udp net.PacketConn

	cc          ClientConn
	acceptTcp   bool
	acceptDgram string
	assocOk     bool

	pair     string
	downlink func(b []byte) error

	alive bool
}

func newUdpAssociation(cc ClientConn, udp net.PacketConn, pair net.Addr) *udpAssociation {
	id := internal.RandUint64()
	ps := ""
	if pair != nil {
		ps = message.AddrString(pair)
	}
	return &udpAssociation{
		id:  id,
		udp: udp,

		cc:          cc,
		acceptTcp:   false,
		assocOk:     false,
		acceptDgram: "......",
		pair:        ps,
	}
}

func (u *udpAssociation) handleTcpUp(ctx context.Context) {
	defer u.exit()
	assocInit := message.UDPHeader{
		Type:          message.UDPMessageAssociationInit,
		AssociationID: u.id,
	}
	if _, err := u.cc.Conn.Write(assocInit.Marshal()); err != nil {
		lg.Warning(err)
		return
	}
	go func() {
		<-time.After(120 * time.Second)
		if !u.assocOk {
			u.exit()
		}
	}()
	for {
		msg, err := message.ParseUDPHeaderFrom(u.cc.Conn)
		if err != nil {
			lg.Warning(err)
			return
		}

		switch msg.Type {
		case message.UDPMessageAssociationAck:
			if !u.assocOk && msg.AssociationID == u.id {
				u.assocOk = true
				u.acceptTcp = true
				u.downlink = func(b []byte) error {
					_, err := u.cc.Conn.Write(b)
					return err
				}
			} else {
				lg.Error(u.cc.ConnId(), "wrong association")
				return
			}
		case message.UDPMessageDatagram:
			if !u.acceptTcp {
				lg.Error(u.cc.ConnId(), "should send association ack via tcp")
				return
			}
			// todo report critical error
			if err := u.send(msg); err != nil {
				lg.Warning(err)
			}
		}
	}
}

func (u *udpAssociation) handleUdpUp(ctx context.Context, cp ClientPacket) {
	msg := cp.Message
	if !u.assocOk {
		if msg.Type == message.UDPMessageAssociationAck && msg.AssociationID == u.id {
			u.assocOk = true
			u.downlink = cp.Downlink
			u.acceptDgram = message.AddrString(cp.Source)
		}
	} else {
		if msg.Type != message.UDPMessageDatagram {
			return
		}
		if err := u.send(msg); err != nil {
			lg.Warning(err)
		}
	}
}

func (u *udpAssociation) handleUdpDown(ctx context.Context) {
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	for {
		l, a, err := u.udp.ReadFrom(buf)
		if err != nil {
			lg.Error("udp read", err)
			return
		}
		msg := &message.UDPHeader{
			Type:          message.UDPMessageDatagram,
			AssociationID: u.id,

			Endpoint: message.ParseAddr(a.String()),
			Data:     internal.Dup(buf[:l]),
		}
		if !u.assocOk || u.downlink == nil {
			continue
		}
		if err := u.downlink(msg.Marshal()); err != nil {
			lg.Error("udp downlink", err)
		}
	}
}

func (u *udpAssociation) send(msg *message.UDPHeader) error {
	a, err := net.ResolveUDPAddr("udp", msg.Endpoint.String())
	if err != nil {
		return err
	}
	_, err = u.udp.WriteTo(msg.Data, a)
	return err
}

func (u *udpAssociation) exit() {
	u.alive = false
	u.cc.Conn.Close()
	u.udp.Close()
}
