package socks6

import (
	"context"
	"net"
	"time"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
	"golang.org/x/sync/semaphore"
)

type backlogListener struct {
	listener net.Listener
	session  []byte
	conn     net.Conn

	sem   semaphore.Weighted
	queue chan net.Conn
	alive bool
}

func newBacklogListener(l net.Listener, session []byte, c net.Conn, backlog uint16) *backlogListener {
	return &backlogListener{
		listener: l,
		session:  session,
		conn:     c,

		sem:   *semaphore.NewWeighted(int64(backlog)),
		queue: make(chan net.Conn, backlog),
		alive: true,
	}
}

// handler check for same session and relay between request connection and an accepted connection
func (b *backlogListener) handler(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	info ClientInfo,
	initData []byte,
) {
	if !internal.ByteArrayEqual(info.SessionID, b.session) {
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplySuccess).Marshal())
		return
	}
	b.sem.Release(1)
	c, ok := <-b.queue
	if !ok {
		// todo is this ok?
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplyConnectionRefused).Marshal())
	}
	rep := message.NewOperationReplyWithCode(message.OperationReplySuccess)
	rep.Endpoint = message.NewAddrMust(b.listener.Addr().String())
	conn.Write(rep.Marshal())
	rep.Endpoint = message.NewAddrMust(c.RemoteAddr().String())
	conn.Write(rep.Marshal())

	relay(ctx, conn, c, 10*time.Minute)
}

// accept accept an incoming connection, notify client, put connection to backlog queue
func (b *backlogListener) accept(ctx context.Context) {
	b.sem.Acquire(ctx, 1)
	c, err := b.listener.Accept()
	if err != nil {
		c.Close()
	}
	b.queue <- c
	rep := message.NewOperationReplyWithCode(message.OperationReplySuccess)
	rep.Endpoint = message.NewAddrMust(c.RemoteAddr().String())
	if _, err := b.conn.Write(rep.Marshal()); err != nil {
		b.conn.Close()
		b.alive = false
	}
}

// worker check client connection alive and call accept
func (b *backlogListener) worker(ctx context.Context) {
	go func() {
		buf := internal.BytesPool16.Rent()
		defer internal.BytesPool16.Return(buf)
		for b.alive {
			if _, err := b.conn.Read(buf); err != nil {
				b.conn.Close()
				b.alive = false
				return
			}
		}
	}()
	for b.alive {
		b.accept(ctx)
	}
}
