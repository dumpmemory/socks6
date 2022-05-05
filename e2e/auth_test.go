package e2e_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/e2e/e2etool"
)

func TestUserPassAuth(t *testing.T) {
	e2etool.WatchDog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discardAddr, _ := e2etool.GetAddr()
	go e2etool.ServeTCP(ctx, discardAddr, e2etool.Discard)

	sAddr, sPort := e2etool.GetAddr()
	proxy := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	sa := auth.NewServerAuthenticator()
	sa.AddMethod(auth.PasswordServerAuthenticationMethod{
		Passwords: map[string]string{
			"alice":   "123456",
			"charlie": "654321",
		},
	})
	proxy.Worker.Authenticator = sa
	proxy.Start(ctx)
	client := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
		Backlog:    10,
		AuthenticationMethod: auth.PasswordClientAuthenticationMethod{
			Username: "alice",
			Password: "123456",
		},
	}
	fd, err := client.Dial("tcp", discardAddr)
	assert.NoError(t, err)
	e2etool.AssertClosed(t, fd)

	clientWrong := socks6.Client{
		Server:     sAddr,
		Encrypted:  false,
		UseSession: false,
		Backlog:    10,
		AuthenticationMethod: auth.PasswordClientAuthenticationMethod{
			Username: "mallory",
			Password: "123456",
		},
	}
	_, err = clientWrong.Dial("tcp", discardAddr)
	assert.Error(t, err)
}

func TestAsyncAuth(t *testing.T) {
	e2etool.WatchDog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discardAddr, _ := e2etool.GetAddr()
	go e2etool.ServeTCP(ctx, discardAddr, e2etool.Discard)

	sAddr, sPort := e2etool.GetAddr()
	proxy := socks6.Server{
		Address:       "127.0.0.1",
		CleartextPort: sPort,
		Worker:        socks6.NewServerWorker(),
	}
	sa := auth.NewServerAuthenticator()
	sa.AddMethod(e2etool.FakeEchoServerAuthenticationMethod{})
	proxy.Worker.Authenticator = sa
	proxy.Start(ctx)
	client := socks6.Client{
		Server:               sAddr,
		Encrypted:            false,
		UseSession:           false,
		Backlog:              10,
		AuthenticationMethod: e2etool.FakeEchoClientAuthenticationMethod{},
	}
	fd, err := client.Dial("tcp", discardAddr)
	assert.NoError(t, err)
	e2etool.AssertClosed(t, fd)
}
