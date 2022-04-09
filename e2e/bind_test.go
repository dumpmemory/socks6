package e2e_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/e2e/e2etool"
)

func TestBind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sAddr, sPort := e2etool.GetAddr()
	s := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	s.Start(ctx)
	c := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
		Backlog:    0,
	}

	l, err := c.Listen("tcp", "0.0.0.0:0")
	assert.NoError(t, err)
	actualAddr := l.Addr().String()
	dl := net.Dialer{
		Timeout: 1 * time.Second,
	}
	fd, err := dl.Dial("tcp", actualAddr)
	assert.NoError(t, err)
	ch := make(chan struct{})
	go func() {
		select {
		case <-time.After(1 * time.Second):
			assert.FailNow(t, "timeout")
		case <-ch:
		}
	}()
	fd2, err := l.Accept()
	assert.NoError(t, err)
	n, err := fd.Write([]byte{1})
	assert.EqualValues(t, 1, n)
	assert.NoError(t, err)
	buf := make([]byte, 10)
	n, err = fd2.Read(buf)
	assert.EqualValues(t, 1, n)
	assert.NoError(t, err)
	fd.Close()

	n, err = fd2.Read(buf)
	assert.EqualValues(t, 0, n)
	assert.Error(t, err)
	ch <- struct{}{}
}
