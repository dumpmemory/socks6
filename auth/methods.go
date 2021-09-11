package auth

import (
	"context"
	"net"
)

type ServerAuthenticationMethod interface {
	Authenticate(
		ctx context.Context,
		conn net.Conn,
		data []byte,
		sac *ServerAuthenticationChannels,
	)
}

type ServerAuthenticationChannels struct {
	Result   chan ServerAuthenticationResult
	Continue chan bool
	Err      chan error
}

func NewServerAuthenticationChannels() *ServerAuthenticationChannels {
	return &ServerAuthenticationChannels{
		Result:   make(chan ServerAuthenticationResult),
		Continue: make(chan bool, 1),  // so 1 step auth can ignore it's input
		Err:      make(chan error, 1), // so auth can exit fast
	}
}
