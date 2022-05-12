package e2e_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/e2e/e2etool"
	"github.com/studentmain/socks6/message"
)

func TestUdp(t *testing.T) {
	e2etool.WatchDog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echoAddr, _ := e2etool.GetAddr()
	go e2etool.ServeUDP(ctx, echoAddr, e2etool.UEcho)
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
	eAddr := message.ParseAddr(echoAddr)
	fd, err := client.UDPAssociateRequest(ctx, message.AddrIPv4Zero, nil)
	assert.NoError(t, err)
	fd.WriteTo([]byte{1}, eAddr)
	buf := make([]byte, 10)
	n, a2, err := fd.ReadFrom(buf)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, n)
	assert.Equal(t, eAddr.String(), a2.String())
	assert.EqualValues(t, 1, buf[0])
}
