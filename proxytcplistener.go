package socks6

import (
	"net"
	"sync"

	"github.com/studentmain/socks6/message"
)

type ProxyTCPListener struct {
	netConn
	bind    net.Addr
	backlog uint16
	// socks6 client, used for accept backlog connection
	client *Client
	// options, used for accept
	op *message.OptionSet
	// accept call lock
	lock sync.Mutex
	// already accepted
	used bool
}

func (t *ProxyTCPListener) Accept() (net.Conn, error) {
	t.lock.Lock()
	if t.used {
		return nil, &net.OpError{}
	}
	// read oprep2
	oprep, err := message.ParseOperationReplyFrom(t.netConn)
	if err != nil {
		t.lock.Unlock()
		return nil, err
	}
	cconn := ProxyTCPConn{
		addrPair: addrPair{
			local:  t.bind,
			remote: oprep.Endpoint,
		},
	}
	if t.backlog == 0 {
		t.used = true
		cconn.netConn = t.netConn
		t.lock.Unlock()
		return &cconn, nil
	} else {
		// unlock asap, BindRequest is time consuming
		t.lock.Unlock()
		tbc, err := t.client.BindRequest(t.bind, t.op)
		if err != nil {
			return nil, err
		}
		return tbc.Accept()
	}
}

// [localaddr]----netConn----[[proxyremoteaddr][addr]]<--

func (t *ProxyTCPListener) Addr() net.Addr {
	return t.bind
}

func (t *ProxyTCPListener) LocalAddr() net.Addr {
	return t.netConn.LocalAddr()
}

func (t *ProxyTCPListener) ProxyRemoteAddr() net.Addr {
	return t.netConn.RemoteAddr()
}
