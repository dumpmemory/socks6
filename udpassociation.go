package socks6

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

// UDPDownlink is a function used to write datagram to specific UDP endpoint
type UDPDownlink func(b []byte) error

// ClientPacket represent a single UDPHeader recieved from client
type ClientPacket struct {
	Message  *message.UDPHeader
	Source   net.Addr
	Downlink UDPDownlink
}

type udpAssociation struct {
	id  uint64
	udp net.PacketConn

	cc          ClientConn
	acceptTcp   bool   // whether to accept datagram over tcp
	acceptDgram string // which client address is accepted
	assocOk     bool   // first datagram recieved

	pair     string // reserved port
	downlink func(b []byte) error

	allowedRemote sync.Map
	addrFilter    bool

	alive bool
}

func newUdpAssociation(
	cc ClientConn,
	udp net.PacketConn,
	pair net.Addr,
	addrFilter bool,
) *udpAssociation {
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

		addrFilter:    addrFilter,
		allowedRemote: sync.Map{},
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
			u.reportErr(err)
			return
		}
		if msg.AssociationID != u.id {
			u.reportErr(errors.New("not same assoc"))
			return
		}
		if msg.Type != message.UDPMessageDatagram {
			continue
		}

		switch msg.Type {
		case message.UDPMessageDatagram:
			if !u.assocOk {
				u.assocOk = true
				u.acceptTcp = true
				u.ack()
				u.downlink = func(b []byte) error {
					_, err := u.cc.Conn.Write(b)
					return err
				}
			}
			if !u.acceptTcp {
				lg.Error(u.cc.ConnId(), "should send association ack via tcp")
				return
			}
			// todo report critical error
			if err := u.send(msg); err != nil {
				u.reportErr(err)
			}
		}
	}
}

func (u *udpAssociation) handleUdpUp(ctx context.Context, cp ClientPacket) {
	msg := cp.Message
	if msg.Type != message.UDPMessageDatagram {
		return
	}
	if msg.AssociationID != u.id {
		u.reportErr(errors.New("not same assoc"))
		return
	}
	// start assoc if necessary
	if !u.assocOk {
		u.assocOk = true
		u.acceptDgram = message.AddrString(cp.Source)
		u.ack()
		u.downlink = cp.Downlink
	}
	if err := u.send(msg); err != nil {
		u.reportErr(err)
	}
}

func (u *udpAssociation) handleUdpDown(ctx context.Context) {
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	for {
		l, a, err := u.udp.ReadFrom(buf)
		if u.addrFilter {
			sa := message.ConvertAddr(a)
			if sa.AddressType == message.AddressTypeDomainName {
				lg.Info("Can't filter remote UDP packet by domain name")
				continue
			}
			if _, ok := u.allowedRemote.Load(net.IP(sa.Address).String()); !ok {
				continue
			}
		}
		if err != nil {
			lg.Error("udp read", err)
			return
		}
		msg := &message.UDPHeader{
			Type:          message.UDPMessageDatagram,
			AssociationID: u.id,

			Endpoint: message.ConvertAddr(a),
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

	if u.addrFilter {
		u.allowedRemote.Store(a.IP.String(), nil)
	}

	if err != nil {
		return err
	}
	_, err = u.udp.WriteTo(msg.Data, a)
	return err
}

func (u *udpAssociation) ack() error {
	h := message.UDPHeader{
		Type:          message.UDPMessageAssociationAck,
		AssociationID: u.id,
	}
	_, err := u.cc.Conn.Write(h.Marshal())
	return err
}

func (u *udpAssociation) exit() {
	u.alive = false
	u.cc.Conn.Close()
	u.udp.Close()
}

func (u *udpAssociation) reportErr(e error) {
	lg.Warning("udp assoc err", e)
}
