package client

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/studentmain/socks6/message"
)

type UDPClient struct {
	base    net.Conn
	uot     bool
	assocId uint64
	uotAck  bool
	rlock   sync.Mutex // needn't write lock, write message is finished in 1 write, but read message is in many read
	assocOk bool
	rbind   net.Addr
}

func (u *UDPClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if u.uot {
		u.rlock.Lock()
		defer u.rlock.Unlock()
	}
	if !u.uotAck && u.uot {
		_, err := message.ParseUDPHeaderFrom(u.base)
		if err != nil {
			return 0, nil, err
		}
	}
	h := message.UDPHeader{}
	if u.uot {
		_, err := message.ParseUDPHeaderFrom(u.base)
		if err != nil {
			return 0, nil, err
		}
	} else {
		buf := make([]byte, 4096)
		l, err := u.base.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		_, err = message.ParseUDPHeaderFrom(bytes.NewReader(buf[:l]))
		if err != nil {
			return 0, nil, err
		}
	}
	if h.AssociationID != u.assocId {
		return 0, nil, message.ErrFormat
	}
	if h.Type != message.UDPMessageDatagram {
		// todo icmp error
		return 0, nil, message.ErrFormat
	}
	addr, err = net.ResolveUDPAddr("udp", h.Endpoint.String())
	if err != nil {
		return 0, nil, err
	}
	ld := len(h.Data)
	lp := len(p)
	if ld > lp {
		n = copy(p, h.Data[:lp])
	} else {
		n = copy(p[:ld], h.Data)
	}
	return
}

func (u *UDPClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	h := message.UDPHeader{
		Type:          message.UDPMessageDatagram,
		AssociationID: u.assocId,
		Endpoint:      message.ParseAddr(addr.String()),
		Data:          p,
	}

	n, err = u.base.Write(h.Marshal())
	return
}

func (u *UDPClient) Close() error {
	return u.base.Close()
}

func (u *UDPClient) LocalAddr() net.Addr {
	return u.base.LocalAddr()
}

func (u *UDPClient) ProxyBindAddr() net.Addr {
	return u.rbind
}
func (u *UDPClient) ProxyRemoteAddr() net.Addr {
	return u.base.RemoteAddr()
}

func (u *UDPClient) SetDeadline(t time.Time) error {
	return u.base.SetDeadline(t)
}
func (u *UDPClient) SetReadDeadline(t time.Time) error {
	return u.base.SetReadDeadline(t)
}
func (u *UDPClient) SetWriteDeadline(t time.Time) error {
	return u.base.SetWriteDeadline(t)
}
