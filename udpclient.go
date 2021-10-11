package socks6

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

type UDPClient struct {
	base    net.Conn // original tcp conn
	conn    net.Conn // data conn
	overTcp bool

	assocId uint64

	rlock sync.Mutex // needn't write lock, write message is finished in 1 write, but read message is in many read
	rbind net.Addr
	icmp  bool

	alive bool
}

func (u *UDPClient) init() error {
	a, err := message.ParseUDPHeaderFrom(u.base)
	if err != nil {
		return err
	}
	if a.Type != message.UDPMessageAssociationInit {
		return errors.New("not a assoc init")
	}
	u.assocId = a.AssociationID
	reply := message.UDPHeader{
		Type:          message.UDPMessageAssociationAck,
		AssociationID: u.assocId,
	}

	if _, err := u.conn.Write(reply.Marshal()); err != nil {
		return err
	}

	if !u.overTcp {
		go func() {
			buf := internal.BytesPool256.Rent()
			defer internal.BytesPool256.Return(buf)
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

func (u *UDPClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	cd := internal.NewCancellableDefer(func() { u.Close() })

	h := message.UDPHeader{}
	if u.overTcp {
		u.rlock.Lock()
		defer u.rlock.Unlock()

		h2, err := message.ParseUDPHeaderFrom(u.conn)
		h = *h2
		if err != nil {
			return 0, nil, err
		}
	} else {
		buf := internal.BytesPool64k.Rent()
		defer internal.BytesPool64k.Return(buf)

		l, err := u.conn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		h2, err := message.ParseUDPHeaderFrom(bytes.NewReader(buf[:l]))
		h = *h2
		if err != nil {
			return 0, nil, err
		}
	}

	if h.AssociationID != u.assocId {
		return 0, nil, message.ErrFormat
	}
	if h.Type == message.UDPMessageError && u.icmp {
		// todo icmp error

	} else if h.Type != message.UDPMessageDatagram {
		return 0, nil, message.ErrFormat
	}
	addr, err = net.ResolveUDPAddr("udp", h.Endpoint.String())
	if err != nil {
		return 0, nil, err
	}
	ld := len(h.Data)
	lp := len(p)
	if ld > lp {
		// data is longer than buf
		n = copy(p, h.Data[:lp])
	} else {
		n = copy(p[:ld], h.Data)
	}

	cd.Cancel()
	return
}

func (u *UDPClient) WriteTo(p []byte, addr net.Addr) (int, error) {
	h := message.UDPHeader{
		Type:          message.UDPMessageDatagram,
		AssociationID: u.assocId,
		Endpoint:      message.ParseAddr(addr.String()),
		Data:          p,
	}

	n, err := u.conn.Write(h.Marshal())
	if err != nil {
		u.Close()
	}
	return n, err
}

func (u *UDPClient) Close() error {
	e1 := u.base.Close()
	e2 := u.conn.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func (u *UDPClient) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

func (u *UDPClient) ProxyBindAddr() net.Addr {
	return u.rbind
}
func (u *UDPClient) ProxyRemoteAddr() net.Addr {
	return u.conn.RemoteAddr()
}

func (u *UDPClient) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}
func (u *UDPClient) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}
func (u *UDPClient) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
}
