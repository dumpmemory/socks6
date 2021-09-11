package auth

import (
	"context"
	"net"
)

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
