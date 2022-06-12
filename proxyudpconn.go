package socks6

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/common/nt"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

// ProxyUDPConn represents a SOCKS 6 UDP client "connection", implements net.PacketConn, net.Conn
type ProxyUDPConn struct {
	origConn   net.Conn     // original tcp conn
	dataConn   nt.SeqPacket // data conn
	overTcp    bool
	expectAddr net.Addr // expected remote addr
	icmp       bool     // accept icmp error report

	assocId uint64

	parseLock sync.Mutex // needn't write lock, write message is finished in 1 write, but read message is in many read
	rbind     net.Addr   // remote bind addr

	acked   bool
	ackwg   sync.WaitGroup
	lastErr error // todo actually use lastErr ?
}

// init setup association
func (u *ProxyUDPConn) init() error {
	// read assoc init
	a, err := message.ParseUDPMessageFrom(u.origConn)
	if err != nil {
		return err
	}
	if a.Type != message.UDPMessageAssociationInit {
		return ErrUnexpectedMessage
	}
	u.assocId = a.AssociationID

	// needn't wait for ACK before read data
	// only server can send data (not true when using raw UDP, but why you use it?)
	// if server start send data, then assoc already established
	// ack is send over tcp:
	// 1. won't lost
	// 2. can be slower than data over udp
	go u.rexmitFirstPacket()
	u.readAck()
	return nil
}

func (u *ProxyUDPConn) rexmitFirstPacket() {
	<-time.After(5 * time.Second)

	// it's possible to have a "smart fallback"
	// first try udp, if no ack, fallback to tcp

	// may cause special radar reflection
	for i := 0; i < 7+rand.Intn(5); i++ {
		// randomized timeout to somehow mitigate it
		ms := time.Duration(rand.Intn(5000)+5000) * time.Millisecond
		<-time.After(ms)
		if u.acked {
			break
		}

		msg := message.UDPMessage{
			Type:          message.UDPMessageDatagram,
			AssociationID: u.assocId,
			Endpoint:      message.AddrIPv4Zero,
			Data:          []byte{},
		}
		err := u.dataConn.Reply(msg.Marshal())
		if err != nil {
			u.lastErr = err
			u.Close()
			return
		}
	}
	u.lastErr = errors.New("timeout")
}

func (u *ProxyUDPConn) readAck() {
	// block TCP read
	// lock when init
	u.parseLock.Lock()
	go func() {
		// unlock when ack read complete
		// to avoid goroutine shedule cause lock delayed
		defer u.parseLock.Unlock()

		ack, err := message.ParseUDPMessageFrom(u.origConn)
		failed := true
		if err != nil {
			u.lastErr = err
		} else if ack.AssociationID != u.assocId {
			u.lastErr = ErrAssociationMismatch
		} else if ack.Type != message.UDPMessageAssociationAck {
			u.lastErr = ErrUnexpectedMessage
		} else {
			failed = false
		}
		u.acked = true

		if failed {
			u.Close()
			return
		}

		if !u.overTcp {
			// tcp conn health checkers
			go func() {
				buf := make([]byte, 256)
				for {
					_, err := u.origConn.Read(buf)
					if err != nil {
						u.lastErr = err
						u.Close()
						return
					}
				}
			}()
		}
	}()
}

// Read implements net.Conn
func (u *ProxyUDPConn) Read(p []byte) (int, error) {
	if u.expectAddr == nil {
		return 0, &net.OpError{
			Op:     "read",
			Net:    "socks6",
			Source: u.LocalAddr(),
			Err:    syscall.EDESTADDRREQ,
		}
	}
	for {
		n, a, e := u.ReadFrom(p)
		if e != nil {
			return 0, e
		}
		if a.String() == u.expectAddr.String() {
			return n, e
		}
	}
}

// ReadFrom implements net.PacketConn
func (u *ProxyUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	lg.Debug("readfrom")
	cd := common.NewCancellableDefer(func() { u.Close() })

	netErr := net.OpError{
		Op:     "readfrom",
		Net:    "socks6",
		Source: u.LocalAddr(),
		Addr:   u.ProxyRemoteAddr(),
	}
	// read message
	h := message.UDPMessage{}
	if u.overTcp {
		u.parseLock.Lock()
		defer u.parseLock.Unlock()

		h2, err := message.ParseUDPMessageFrom(u.origConn)
		h = *h2
		if err != nil {
			netErr.Err = err
			return 0, nil, &netErr
		}
	} else {
		// good old "UDP packet size" problem
		// also cause some radar "reflection" (UDP is known for it's low RCS, so not a big problem)
		// UDP allow 64k, path MTU usually not, but IP fragmentation
		buf := internal.BytesPool4k.Rent()
		defer internal.BytesPool4k.Return(buf)

		d, err := u.dataConn.NextDatagram()
		if err != nil {
			netErr.Err = err
			return 0, nil, &netErr
		}
		h2, err := message.ParseUDPMessageFrom(bytes.NewReader(d.Data()))
		h = *h2
		if err != nil {
			netErr.Err = err
			return 0, nil, err
		}
	}

	// silently drop to avoid DoS? is it possible or necessary (it's only possible in plaintext)?
	if h.AssociationID != u.assocId {
		netErr.Err = ErrAssociationMismatch
		return 0, nil, &netErr
	}
	if h.Type == message.UDPMessageError && u.icmp {
		netErr.Err = convertIcmpError(h)
		return 0, nil, &netErr
	} else if h.Type != message.UDPMessageDatagram {
		netErr.Err = ErrUnexpectedMessage
		return 0, nil, &netErr
	}
	// resolve as udp address
	addr, err := net.ResolveUDPAddr("udp", h.Endpoint.String())
	if err != nil {
		netErr.Err = err
		return 0, nil, &netErr
	}
	// copy data to buffer
	ld := len(h.Data)
	lp := len(p)
	n := 0
	if ld > lp {
		// data is longer than buf
		n = copy(p, h.Data[:lp])
	} else {
		n = copy(p[:ld], h.Data)
	}

	cd.Cancel()
	return n, addr, nil
}

// Write implements net.Conn
func (u *ProxyUDPConn) Write(p []byte) (int, error) {
	if u.expectAddr == nil {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "socks6",
			Source: u.LocalAddr(),
			Err:    syscall.EDESTADDRREQ,
		}
	}
	return u.WriteTo(p, u.expectAddr)
}

// WriteTo implements net.PacketConn
func (u *ProxyUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	netErr := net.OpError{
		Op:     "writeto",
		Net:    "socks6",
		Source: u.LocalAddr(),
		Addr:   u.ProxyRemoteAddr(),
	}
	if netErr.Err != nil {
		u.Close()
		return 0, &netErr
	}

	h := message.UDPMessage{
		Type:          message.UDPMessageDatagram,
		AssociationID: u.assocId,
		Endpoint:      message.ConvertAddr(addr),
		Data:          p,
	}

	err := u.dataConn.Reply(h.Marshal())
	if err != nil {
		netErr.Err = err
		u.Close()
		return 0, &netErr
	}
	return len(p), nil
}

func (u *ProxyUDPConn) Close() error {
	u.acked = true
	e1 := u.origConn.Close()
	e2 := u.dataConn.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

// LocalAddr return client-proxy connection's client side address
func (u *ProxyUDPConn) LocalAddr() net.Addr {
	return u.dataConn.LocalAddr()
}

func (u *ProxyUDPConn) RemoteAddr() net.Addr {
	return u.expectAddr
}

// ProxyBindAddr return proxy's outbound address
func (u *ProxyUDPConn) ProxyBindAddr() net.Addr {
	return u.rbind
}

// ProxyRemoteAddr return client-proxy connection's proxy side address
func (u *ProxyUDPConn) ProxyRemoteAddr() net.Addr {
	return u.dataConn.RemoteAddr()
}

func (u *ProxyUDPConn) SetDeadline(t time.Time) error {
	return u.dataConn.SetDeadline(t)
}
func (u *ProxyUDPConn) SetReadDeadline(t time.Time) error {
	return u.dataConn.SetReadDeadline(t)
}
func (u *ProxyUDPConn) SetWriteDeadline(t time.Time) error {
	return u.dataConn.SetWriteDeadline(t)
}

func convertIcmpError(msg message.UDPMessage) error {
	switch msg.ErrorCode {
	case message.UDPErrorNetworkUnreachable:
		return syscall.ENETUNREACH
	case message.UDPErrorHostUnreachable:
		return syscall.EHOSTUNREACH
	case message.UDPErrorTTLExpired:
		return ErrTTLExpired
	case message.UDPErrorDatagramTooBig:
		return syscall.E2BIG
	}
	lg.Panic("not implemented icmp error conversion")
	return nil
}
