package socks6

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

// ProxyUDPConn represents a SOCKS 6 UDP client "connection", implements net.PacketConn, net.Conn
type ProxyUDPConn struct {
	base       net.Conn // original tcp conn
	conn       net.Conn // data conn
	overTcp    bool
	expectAddr net.Addr // expected remote addr
	icmp       bool     // accept icmp error report

	assocId uint64

	parseLock sync.Mutex // needn't write lock, write message is finished in 1 write, but read message is in many read
	rbind     net.Addr   // remote bind addr

	ackDone sync.WaitGroup
	runAck  sync.Once
}

// init setup association
func (u *ProxyUDPConn) init() error {
	// read assoc init
	a, err := message.ParseUDPMessageFrom(u.base)
	if err != nil {
		return err
	}
	if a.Type != message.UDPMessageAssociationInit {
		return errors.New("not assoc init")
	}
	u.assocId = a.AssociationID
	u.ackDone.Add(1)

	if !u.overTcp {
		// tcp conn health checkers
		go func() {
			u.ackDone.Wait()
			buf := make([]byte, 256)
			for {
				_, err := u.base.Read(buf)
				// todo improve error report
				if err != nil {
					u.Close()
					return
				}
			}
		}()
	}
	return nil
}

func (u *ProxyUDPConn) readAck() error {
	ack, err := message.ParseUDPMessageFrom(u.base)
	if err != nil {
		return err
	}
	if ack.AssociationID != u.assocId {
		return errors.New("not same association")
	}
	if ack.Type != message.UDPMessageAssociationAck {
		return errors.New("not assoc ack message")
	}
	u.ackDone.Done()
	return nil
}

// Read implements net.Conn
func (u *ProxyUDPConn) Read(p []byte) (int, error) {
	if u.expectAddr == nil {
		return 0, &net.OpError{
			Op:     "read",
			Net:    "socks6",
			Source: u.LocalAddr(),
			Err:    errors.New("use Dial to create connection"),
		}
	}
	for {
		n, a, e := u.ReadFrom(p)
		if e != nil {
			return 0, e
		}
		if message.AddrString(a) == message.AddrString(u.expectAddr) {
			return n, e
		}
	}
}

// ReadFrom implements net.PacketConn
func (u *ProxyUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	u.ackDone.Wait()
	cd := internal.NewCancellableDefer(func() { u.Close() })

	netErr := net.OpError{
		Op:     "read",
		Net:    "socks6",
		Source: u.LocalAddr(),
		Addr:   u.ProxyRemoteAddr(),
	}
	// read message
	h := message.UDPMessage{}
	if u.overTcp {
		u.parseLock.Lock()
		defer u.parseLock.Unlock()

		h2, err := message.ParseUDPMessageFrom(u.conn)
		h = *h2
		if err != nil {
			netErr.Err = err
			return 0, nil, &netErr
		}
	} else {
		buf := internal.BytesPool64k.Rent()
		defer internal.BytesPool64k.Return(buf)

		l, err := u.conn.Read(buf)
		if err != nil {
			netErr.Err = err
			return 0, nil, &netErr
		}
		h2, err := message.ParseUDPMessageFrom(bytes.NewReader(buf[:l]))
		h = *h2
		if err != nil {
			netErr.Err = err
			return 0, nil, err
		}
	}

	if h.AssociationID != u.assocId {
		netErr.Err = errors.New("assoc mismatch")
		return 0, nil, &netErr
	}
	if h.Type == message.UDPMessageError && u.icmp {
		netErr.Err = convertIcmpError(h)
		return 0, nil, &netErr
	} else if h.Type != message.UDPMessageDatagram {
		netErr.Err = errors.New("not udp datagram message")
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
			Err:    errors.New("use Dial to create connection"),
		}
	}
	return u.WriteTo(p, u.expectAddr)
}

// WriteTo implements net.PacketConn
func (u *ProxyUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	netErr := net.OpError{
		Op:     "write",
		Net:    "socks6",
		Source: u.LocalAddr(),
		Addr:   u.ProxyRemoteAddr(),
	}
	u.runAck.Do(func() {
		netErr.Err = u.readAck()
	})
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

	n, err := u.conn.Write(h.Marshal())
	if err != nil {
		netErr.Err = err
		u.Close()
		return 0, &netErr
	}
	return n, nil
}

func (u *ProxyUDPConn) Close() error {
	e1 := u.base.Close()
	e2 := u.conn.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

// LocalAddr return client-proxy connection's client side address
func (u *ProxyUDPConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
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
	return u.conn.RemoteAddr()
}

func (u *ProxyUDPConn) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}
func (u *ProxyUDPConn) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}
func (u *ProxyUDPConn) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
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
