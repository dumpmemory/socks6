package auth

import (
	"context"
	"net"
)

const authIdNone byte = 2

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
func (f NoneServerAuthenticationMethod) ID() byte {
	return authIdNone
}

type NoneClientAuthenticationMethod struct{}

func (f NoneClientAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	cac ClientAuthenticationChannels,
) {
	cac.Data <- []byte{}
	rep1 := <-cac.FirstAuthReply
	cac.FinalAuthReply <- rep1
	cac.Error <- nil
}
func (f NoneClientAuthenticationMethod) ID() byte {
	return authIdNone
}
