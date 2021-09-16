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
		Result:   make(chan ServerAuthenticationResult, 2),
		Continue: make(chan bool, 1),
		Err:      make(chan error, 1),
	}
}
