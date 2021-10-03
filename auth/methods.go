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

// ServerAuthenticationChannels are three channels used to control auth step 2
type ServerAuthenticationChannels struct {
	// Result is where authenticate method write it's result
	Result chan ServerAuthenticationResult
	// Continue is used by server process to signal auth step 1 result has been written to client
	Continue chan bool
	// Err used by authn method to report error
	Err chan error
}

func NewServerAuthenticationChannels() *ServerAuthenticationChannels {
	return &ServerAuthenticationChannels{
		Result:   make(chan ServerAuthenticationResult, 2),
		Continue: make(chan bool, 1),
		Err:      make(chan error, 1),
	}
}
