package client

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/internal/lg"
	"github.com/studentmain/socks6/message"
)

type Client struct {
	ProxyHost     string
	EncryptedPort uint16
	CleartextPort uint16

	UDPOverTCP bool
	Dialer     net.Dialer
}

func (c *Client) Dial(network string, addr string) (net.Conn, error) {
	tcc := TCPConnectClient{}
	sconn, err := c.makeStreamConn()
	if err != nil {
		return nil, err
	}
	_, err = sconn.Write((&message.Request{
		CommandCode: message.CommandConnect,
		Endpoint:    message.NewAddrMust(addr),
	}).Marshal())
	if err != nil {
		return nil, err
	}
	tcc.base = sconn
	tcc.remote = message.NewAddrMust(addr)
	// todo auth
	_, err = message.ParseAuthenticationReplyFrom(sconn)
	if err != nil {
		return nil, err
	}
	opr, err := message.ParseOperationReplyFrom(sconn)
	if err != nil {
		return nil, err
	}
	if opr.ReplyCode != 0 {
		return nil, errors.New("operation reply fail")
	}
	return &tcc, nil
}

func (c *Client) Listen(network string, addr string) (net.Listener, error) {
	return nil, nil
}

func (c *Client) ListenUDP(network string, addr string) (net.PacketConn, error) {
	uc := UDPClient{
		uot: c.UDPOverTCP,
	}
	sconn, err := c.makeStreamConn()
	if err != nil {
		return nil, err
	}
	_, err = sconn.Write((&message.Request{
		CommandCode: message.CommandUdpAssociate,
		Endpoint:    message.NewAddrMust(addr),
	}).Marshal())
	if err != nil {
		return nil, err
	}
	ar, err := message.ParseAuthenticationReplyFrom(sconn)
	if err != nil {
		return nil, err
	}
	if ar.Type != message.AuthenticationReplySuccess {
		return nil, errors.New("auth fail")
	}
	opr, err := message.ParseOperationReplyFrom(sconn)
	if err != nil {
		return nil, err
	}
	if opr.ReplyCode != message.OperationReplySuccess {
		return nil, errors.New("op fail")
	}
	u1, err := message.ParseUDPHeaderFrom(sconn)
	if err != nil {
		return nil, err
	}
	uc.assocId = u1.AssociationID

	if uc.uot {
		uc.base = sconn
	} else {
		uc.assocOk = true
		go func() {
			for {
				rb := make([]byte, 256)
				_, err := sconn.Read(rb)
				if err != nil {
					uc.assocOk = false
				}
			}
		}()
		uc.base, err = c.makeDGramConn()
		if err != nil {
			return nil, err
		}
	}

	return &uc, nil
}

func (c *Client) makeStreamConn() (net.Conn, error) {
	var nc net.Conn
	if c.EncryptedPort != 0 {
		lg.Debug("connect via tls")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.EncryptedPort), 10))
		conn, err := c.Dialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		pc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		nc = pc
	} else {
		lg.Debug("connect via tcp")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.CleartextPort), 10))
		pc, err := c.Dialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		nc = pc
	}

	return nc, nil
}

func (c *Client) makeDGramConn() (net.Conn, error) {
	var nc net.Conn
	if c.EncryptedPort != 0 {
		lg.Debug("connect via dtls")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.EncryptedPort), 10))
		conn, err := c.Dialer.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
		pc, err := dtls.Client(conn, &dtls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		nc = pc
	} else {
		lg.Debug("connect via udp")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.CleartextPort), 10))
		pc, err := c.Dialer.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
		nc = pc
	}
	return nc, nil
}

func (c *Client) bind(conn net.Conn, isAccept bool) error {
	//todo
	return nil
}

func (c *Client) auth(req *message.Request) error {
	return nil
}

type UDPClient struct {
	base    net.Conn
	uot     bool
	assocId uint64
	uotAck  bool
	rlock   sync.Mutex // needn't write lock, write message is finished in 1 write, but read message is in many read
	assocOk bool
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
	h.Endpoint.Net = "udp"
	addr = h.Endpoint
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
		Endpoint:      message.NewAddrMust(addr.String()),
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

func (u *UDPClient) SetDeadline(t time.Time) error {
	return u.base.SetDeadline(t)
}
func (u *UDPClient) SetReadDeadline(t time.Time) error {
	return u.base.SetReadDeadline(t)
}
func (u *UDPClient) SetWriteDeadline(t time.Time) error {
	return u.base.SetWriteDeadline(t)
}

type TCPBindClient struct {
	base    net.Conn
	backlog uint16
	c       Client
	lock    sync.Mutex
}

func (t *TCPBindClient) Accept() (net.Conn, error) {
	t.lock.Lock()
	oprep := message.OperationReply{}
	// read oprep2
	_, err := message.ParseOperationReplyFrom(t.base)
	if err != nil {
		t.lock.Unlock()
		return nil, err
	}
	tbc := tcpBindConn{
		remote: oprep.Endpoint,
	}
	if t.backlog == 0 {
		tbc.base = t.base
		t.lock.Unlock()
		return &tbc, nil
	} else {
		t.lock.Unlock()
		conn, err := t.c.makeStreamConn()
		if err != nil {
			return nil, err
		}
		tbc.base = conn
		err = t.c.bind(conn, true)
		if err != nil {
			return nil, err
		}
	}
	return tbc, nil
}

func (t *TCPBindClient) Close() error {
	return t.base.Close()
}

func (t *TCPBindClient) Addr() net.Addr {
	return t.base.LocalAddr()
}

type tcpBindConn struct {
	base   net.Conn
	remote net.Addr
}

func (t tcpBindConn) Read(b []byte) (n int, err error) {
	return t.base.Read(b)
}

func (t tcpBindConn) Write(b []byte) (n int, err error) {
	return t.base.Write(b)
}

func (t tcpBindConn) Close() error {
	return t.base.Close()
}

func (t tcpBindConn) LocalAddr() net.Addr {
	return t.base.LocalAddr()
}

func (t tcpBindConn) RemoteAddr() net.Addr {
	return t.remote
}

func (tc tcpBindConn) SetDeadline(t time.Time) error {
	return tc.base.SetDeadline(t)
}

func (tc tcpBindConn) SetReadDeadline(t time.Time) error {
	return tc.base.SetReadDeadline(t)
}

func (tc tcpBindConn) SetWriteDeadline(t time.Time) error {
	return tc.base.SetWriteDeadline(t)
}

type TCPConnectClient struct {
	base   net.Conn
	remote net.Addr
}

func (t *TCPConnectClient) Read(b []byte) (n int, err error) {
	return t.base.Read(b)
}

func (t *TCPConnectClient) Write(b []byte) (n int, err error) {
	return t.base.Write(b)
}

func (t *TCPConnectClient) Close() error {
	return t.base.Close()
}

func (t *TCPConnectClient) LocalAddr() net.Addr {
	return t.base.LocalAddr()
}

func (t *TCPConnectClient) RemoteAddr() net.Addr {
	return t.remote
}

func (tc *TCPConnectClient) SetDeadline(t time.Time) error {
	return tc.base.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (tc *TCPConnectClient) SetReadDeadline(t time.Time) error {
	return tc.base.SetReadDeadline(t)
}

func (tc *TCPConnectClient) SetWriteDeadline(t time.Time) error {
	return tc.base.SetWriteDeadline(t)
}
