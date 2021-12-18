package socks6

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

// DatagramDownlink is a function used to write datagram to specific UDP endpoint
type DatagramDownlink func(b []byte) error

// ClientPacket represent a single UDPHeader recieved from client
type ClientPacket struct {
	Message  *message.UDPMessage
	Source   net.Addr
	Downlink DatagramDownlink
}

// udpAssociation contain UDP association state
type udpAssociation struct {
	id  uint64
	udp net.PacketConn

	cc          ClientConn
	acceptTcp   bool   // whether to accept datagram over tcp
	acceptDgram string // which client address is accepted
	assocOk     bool   // first datagram recieved
	icmpOn      bool

	pair     string // reserved port
	downlink func(b []byte) error

	allowedRemote sync.Map // allowed remote host
	addrFilter    bool     // when true, only datagram from allowedRemote will send to client

	alive bool
}

func newUdpAssociation(
	cc ClientConn,
	udp net.PacketConn,
	pair net.Addr,
	addrFilter bool,
	icmpOn bool,
) *udpAssociation {
	id := internal.RandUint64()
	ps := ""
	if pair != nil {
		ps = pair.String()
	}
	return &udpAssociation{
		id:  id,
		udp: udp,

		cc:          cc,
		acceptTcp:   false,
		assocOk:     false,
		acceptDgram: "......",
		pair:        ps,
		icmpOn:      icmpOn,

		addrFilter:    addrFilter,
		allowedRemote: sync.Map{},
	}
}

// handleTcpUp process UDP association setup and read messages from initial TCP connection
func (u *udpAssociation) handleTcpUp(ctx context.Context) {
	defer u.exit()
	// send assoc init message
	assocInit := message.UDPMessage{
		Type:          message.UDPMessageAssociationInit,
		AssociationID: u.id,
	}
	if _, err := u.cc.Conn.Write(assocInit.Marshal()); err != nil {
		lg.Warning(err)
		return
	}
	// check for assoc established in ??? seconds
	// and close assoc if not established
	go func() {
		<-time.After(120 * time.Second)
		if !u.assocOk {
			u.exit()
		}
	}()
	// read loop
	for {
		msg, err := message.ParseUDPMessageFrom(u.cc.Conn)
		if err != nil {
			u.reportErr(err)
			return
		}
		if msg.AssociationID != u.id {
			u.reportErr(ErrAssociationMismatch)
			return
		}

		switch msg.Type {
		// switch-case, in case client can send other message in the future
		case message.UDPMessageDatagram:
			// assoc is not established yet
			if !u.assocOk {
				u.assocOk = true
				u.acceptTcp = true
				u.ack()
				u.downlink = func(b []byte) error {
					_, err := u.cc.Conn.Write(b)
					return err
				}
			}
			// assoc is not on tcp
			if !u.acceptTcp {
				lg.Error(u.cc.ConnId(), "should send association ack via tcp first")
				return
			}
			// todo report critical error
			if err := u.send(msg); err != nil {
				u.reportErr(err)
			}
		}
	}
}

// handleUdpUp process a messages from UDP
func (u *udpAssociation) handleUdpUp(ctx context.Context, cp ClientPacket) {
	msg := cp.Message
	if msg.Type != message.UDPMessageDatagram {
		return
	}
	if msg.AssociationID != u.id {
		u.reportErr(ErrAssociationMismatch)
		return
	}
	// start assoc if necessary
	if !u.assocOk {
		u.assocOk = true
		u.acceptDgram = cp.Source.String()
		u.ack()
		u.downlink = cp.Downlink
	}
	if u.acceptDgram != cp.Source.String() {
		lg.Error(u.cc.ConnId(), "should send association ack via udp first")
		return
	}
	if err := u.send(msg); err != nil {
		u.reportErr(err)
	}
}

// handleUdpDown read UDP packet from remote
func (u *udpAssociation) handleUdpDown(ctx context.Context) {
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	for {
		l, a, err := u.udp.ReadFrom(buf)
		// restricted cone nat
		if u.addrFilter {
			sa := message.ConvertAddr(a)
			if sa.AddressType == message.AddressTypeDomainName {
				lg.Info("can't filter remote UDP packet by domain name")
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
		msg := &message.UDPMessage{
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

// handleIcmpDown send an socks 6 icmp message to client
func (u *udpAssociation) handleIcmpDown(ctx context.Context, code message.UDPErrorType, src, dst, reporter *message.SocksAddr) {
	uh := message.UDPMessage{
		Type:          message.UDPMessageError,
		AssociationID: u.id,
		Endpoint:      dst,
		ErrorEndpoint: reporter,
		ErrorCode:     code,
	}
	if err := u.send(&uh); err != nil {
		u.reportErr(err)
	}
}

// send write client udp message to remote
func (u *udpAssociation) send(msg *message.UDPMessage) error {
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

// ack send assoc ack message
func (u *udpAssociation) ack() error {
	h := message.UDPMessage{
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
