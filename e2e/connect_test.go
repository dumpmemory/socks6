package e2e_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/e2e/e2etool"
)

func TestConnect(t *testing.T) {
	e2etool.WatchDog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echoAddr, _ := e2etool.GetAddr()
	go e2etool.ServeTCP(ctx, echoAddr, e2etool.Echo)
	sAddr, sPort := e2etool.GetAddr()
	server := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	server.Start(ctx)
	client := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
	}
	fd, err := client.Dial("tcp", echoAddr)
	assert.NoError(t, err)
	fd.Write([]byte{1})
	buf := make([]byte, 10)
	n, err := fd.Read(buf)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, n)
	assert.EqualValues(t, 1, buf[0])
	err = fd.Close()
	assert.NoError(t, err)
}
