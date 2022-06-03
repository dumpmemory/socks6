package socks6

import (
	"context"
	"net"

	"golang.org/x/sync/semaphore"
)

type backlogListener struct {
	listener net.Listener // listener used for accepting inbound connection

	ctx    context.Context
	cancel func()

	sem semaphore.Weighted // limiting server accepted connection count
	e   error
}

func newBacklogListener(ctx context.Context, l net.Listener, b uint16) *backlogListener {
	c2, cancel := context.WithCancel(ctx)
	return &backlogListener{
		listener: l,
		ctx:      c2,
		cancel:   cancel,
		sem:      *semaphore.NewWeighted(int64(b)),
	}
}

func (b backlogListener) Accept() (net.Conn, error) {
	if err := b.sem.Acquire(b.ctx, 1); err != nil {
		b.e = err
		return nil, b.e
	}
	defer b.sem.Release(1)
	if b.e != nil {
		return nil, b.e
	}
	c, err := b.listener.Accept()
	if err != nil {
		b.e = err
		return nil, err
	}
	return c, nil
}

func (b backlogListener) Close() error {
	b.cancel()
	return b.listener.Close()
}
