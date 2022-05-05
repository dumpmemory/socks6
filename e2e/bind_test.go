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
	e2etool.WatchDog()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sAddr, sPort := e2etool.GetAddr()
	proxy := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	proxy.Start(ctx)
	client := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
		Backlog:    0,
	}

	cListener, err := client.Listen("tcp", "0.0.0.0:0")
	assert.NoError(t, err)
	actualAddr := cListener.Addr().String()

	dialer := net.Dialer{
		Timeout: 1 * time.Second,
	}
	testFd, err := dialer.Dial("tcp", actualAddr)
	assert.NoError(t, err)
	clientFd, err := cListener.Accept()
	assert.NoError(t, err)
	n, err := testFd.Write([]byte{1})
	assert.EqualValues(t, 1, n)
	assert.NoError(t, err)

	e2etool.AssertRead(t, clientFd, []byte{1})
	assert.EqualValues(t, 1, n)
	assert.NoError(t, err)
	testFd.Close()
	e2etool.AssertClosed(t, clientFd)
}

func TestBacklogBind(t *testing.T) {
	e2etool.WatchDog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sAddr, sPort := e2etool.GetAddr()
	proxy := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	proxy.Start(ctx)
	client := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
		Backlog:    10,
	}

	cListener, err := client.Listen("tcp", "0.0.0.0:0")
	assert.NoError(t, err)
	actualAddr := cListener.Addr().String()

	dialer := net.Dialer{
		Timeout: 1 * time.Second,
	}
	testFd1, err := dialer.Dial("tcp", actualAddr)
	assert.NoError(t, err)
	testFd2, err := dialer.Dial("tcp", actualAddr)
	assert.NoError(t, err)

	clientFd1, err := cListener.Accept()
	assert.NoError(t, err)
	clientFd2, err := cListener.Accept()
	assert.NoError(t, err)

	_, err = clientFd1.Write([]byte{1})
	assert.NoError(t, err)
	e2etool.AssertRead(t, testFd1, []byte{1})

	_, err = clientFd2.Write([]byte{1})
	assert.NoError(t, err)
	e2etool.AssertRead(t, testFd2, []byte{1})

	clientFd2.Close()

	_, err = clientFd1.Write([]byte{1})
	assert.NoError(t, err)
	e2etool.AssertRead(t, testFd1, []byte{1})

	testFd1.Close()
}
