package client

import (
	"net"
	"sync"
	"time"

	"github.com/studentmain/socks6/message"
)

type TCPBindClient struct {
	base    net.Conn
	backlog uint16
	c       Client
	lock    sync.Mutex
	used    bool
}

func (t *TCPBindClient) Accept() (net.Conn, error) {
	t.lock.Lock()
	if t.used {
		return nil, &net.OpError{}
	}
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
		t.used = true
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
