package auth

import (
	"context"
	"net"

	"github.com/studentmain/socks6/message"
)

// NoneServerAuthenticationMethod is IANA method 0, require no authn at all
type NoneServerAuthenticationMethod struct{}

func (n NoneServerAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	data []byte,
	sac *ServerAuthenticationChannels,
) {
	sac.Result <- ServerAuthenticationResult{
		Success: true,
	}
	sac.Err <- nil
}

type NoneClientAuthenticationMethod struct{}

func (f NoneClientAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	cac ClientAuthenticationChannels,
) (*message.AuthenticationReply, error) {
	cac.Data <- []byte{}
	rep1 := <-cac.FirstAuthReply
	return rep1, nil
}
