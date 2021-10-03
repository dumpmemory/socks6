package auth

import (
	"context"
	"net"
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
