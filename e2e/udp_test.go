package e2e_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/e2e/e2etool"
	"github.com/studentmain/socks6/message"
)

func TestUDP(t *testing.T) {
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
	fd, err := client.ListenPacketContext(ctx, "udp", ":0")
	assert.NoError(t, err)
	fd.WriteTo([]byte{1}, eAddr)
	buf := make([]byte, 10)
	n, a2, err := fd.ReadFrom(buf)
	if assert.NoError(t, err) {
		assert.EqualValues(t, 1, n)
		assert.Equal(t, eAddr.String(), a2.String())
		assert.EqualValues(t, 1, buf[0])
	}
}

func TestUDPOverTCP(t *testing.T) {
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
		UDPOverTCP: true,
	}
	fd, err := client.DialContext(ctx, "udp", echoAddr)
	assert.NoError(t, err)
	fd.Write([]byte{1})
	buf := make([]byte, 10)
	n, err := fd.Read(buf)
	if assert.NoError(t, err) {
		assert.EqualValues(t, 1, n)
		assert.EqualValues(t, 1, buf[0])
	}
}
