package auth

import (
	"context"
	"crypto/rand"
	"io"
	"net"

	"github.com/studentmain/socks6/message"
)

const AuthenticationMethodFakeEcho = 0xaa

// FakeEchoServerAuthenticationMethod is a fake auth method to test interactive authentication phase
type FakeEchoServerAuthenticationMethod struct{}

func (f FakeEchoServerAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	data []byte,
	sac *ServerAuthenticationChannels,
) {
	buf := []byte{0}
	rand.Read(buf)
	expected := buf[0]

	sac.Result <- ServerAuthenticationResult{
		Success:    false,
		MethodData: buf,
		Continue:   true,
	}
	selected := <-sac.Continue
	// not selected
	if !selected {
		sac.Err <- nil
	}

	if _, err := io.ReadFull(conn, buf); err != nil {
		sac.Err <- err
	}
	if expected != buf[0] {
		sac.Result <- ServerAuthenticationResult{
			Success: false,
		}
	} else {
		sac.Result <- ServerAuthenticationResult{
			Success: true,
		}
	}
	sac.Err <- nil
}

type FakeEchoClientAuthenticationMethod struct{}

func (f FakeEchoClientAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	cac ClientAuthenticationChannels,
) (*message.AuthenticationReply, error) {
	cac.Data <- []byte{}
	rep1 := <-cac.FirstAuthReply
	df, _ := rep1.Options.GetDataF(message.OptionKindAuthenticationData, func(o message.Option) bool {
		return o.Data.(message.AuthenticationDataOptionData).Method == AuthenticationMethodFakeEcho
	})
	if _, err := conn.Write(df.(message.AuthenticationDataOptionData).Data); err != nil {
		return nil, err
	}
	return message.ParseAuthenticationReplyFrom(conn)
}
