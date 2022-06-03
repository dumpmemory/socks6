package socks6

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/message"
	"golang.org/x/sync/semaphore"
)

// backlogBindWorker is used for process backlog enabled bind
type backlogBindWorker struct {
	listener net.Listener // listener used for accepting inbound connection
	cc       SocksConn    // original ClientConn

	sem   semaphore.Weighted // limiting server accepted connection count
	queue chan net.Conn      // server accepted connection queue
	alive bool               // indicate listener is working
}

func newBacklogBindWorker(l net.Listener, cc SocksConn, backlog uint16) *backlogBindWorker {
	return &backlogBindWorker{
		listener: l,
		cc:       cc,

		sem:   *semaphore.NewWeighted(int64(backlog)),
		queue: make(chan net.Conn, backlog),
		alive: true,
	}
}

// handler relay between an accept request connection and a server accepted connection
func (b *backlogBindWorker) handler(
	ctx context.Context,
	cc SocksConn,
) {
	// common handshake step is completed
	// check for same session
	if !bytes.Equal(cc.Session, b.cc.Session) {
		lg.Warning(cc.ConnId(), "session mismatch")
		cc.WriteReplyCode(message.OperationReplyConnectionRefused)
		return
	}
	// "consume" a conn
	b.sem.Release(1)
	c, ok := <-b.queue
	if !ok {
		// todo is this ok?
		cc.WriteReplyCode(message.OperationReplyServerFailure)
	}
	// write bind request reply 1 with listener addr
	rep := message.NewOperationReplyWithCode(message.OperationReplySuccess)
	rep.Endpoint = message.ConvertAddr(b.listener.Addr())
	cc.WriteReplyAddr(message.OperationReplySuccess, b.listener.Addr())

	// write bind request reply 2 with remote addr
	rep.Endpoint = message.ConvertAddr(c.RemoteAddr())
	cc.WriteReplyAddr(message.OperationReplySuccess, c.RemoteAddr())

	// fwd
	relay(ctx, cc.Conn, c, 10*time.Minute)
}

// accept accept an incoming connection, notify client, put connection to queue
func (b *backlogBindWorker) accept(ctx context.Context) {
	// accept and enqueue
	b.sem.Acquire(ctx, 1)
	c, err := b.listener.Accept()

	if err != nil {
		lg.Debug(b.cc.ConnId(), "backlog accept fail", err)
		b.close(err)
		return
	}
	b.queue <- c
	// notify client with operation reply
	rep := message.NewOperationReplyWithCode(message.OperationReplySuccess)
	rep.Endpoint = message.ParseAddr(c.RemoteAddr().String())

	lg.Info(b.cc.ConnId(), "backlog accepted from", conn3Tuple(c))
	if err := b.cc.WriteReplyAddr(message.OperationReplySuccess, c.RemoteAddr()); err != nil {
		lg.Warning(b.cc.ConnId(), "backlog write reply fail", err)
		b.close(err)
	}
}

// worker check client connection alive and call accept
func (b *backlogBindWorker) worker(ctx context.Context) {
	// check conn ok by reading forever
	go func() {
		buf := make([]byte, 16)
		b.cc.Conn.SetReadDeadline(time.Time{})
		for b.alive {
			if _, err := b.cc.Conn.Read(buf); err != nil {
				lg.Trace(b.cc.ConnId(), "read fail, closing backlog listener")
				b.close(err)
				return
			}
		}
	}()
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	// close self when context done
	go func() {
		<-ctx2.Done()
		b.close(ctx.Err())
	}()
	// accept loop
	for b.alive {
		b.accept(ctx)
	}
}

// close close listener and initial connection
func (b *backlogBindWorker) close(err error) {
	if !b.alive {
		return
	}
	b.alive = false
	lg.Warning("close backlog listener", err)
	b.listener.Close()
	b.cc.Conn.Close()
}
