package socks6

import (
	"context"
	"net"
	"sync"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

type ProxyTCPListener struct {
	netConn netConn
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

var _ net.Listener = &ProxyTCPListener{}

func (t *ProxyTCPListener) Accept() (net.Conn, error) {
	return t.AcceptContext(context.Background())
}

func (t *ProxyTCPListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	if t.used {
		return nil, &net.OpError{}
	}

	t.lock.Lock()

	unlock := internal.NewCancellableDefer(func() {
		t.lock.Unlock()
	})
	defer unlock.Defer()

	// read oprep2
	oprep, err := message.ParseOperationReplyFrom(t.netConn)
	if err != nil {
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
		return &cconn, nil
	} else {
		// unlock asap, BindRequest is time consuming
		unlock.Cancel()
		t.lock.Unlock()

		subListener, err := t.client.BindRequest(ctx, t.bind, t.op)
		if err != nil {
			return nil, err
		}
		return subListener.AcceptContext(ctx)
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

func (t *ProxyTCPListener) Close() error {
	return t.netConn.Close()
}
