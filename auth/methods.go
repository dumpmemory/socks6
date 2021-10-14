package auth

import (
	"context"
	"net"

	"github.com/studentmain/socks6/message"
)

type ServerAuthenticationMethod interface {
	Authenticate(
		ctx context.Context,
		conn net.Conn,
		data []byte,
		sac *ServerAuthenticationChannels,
	)
	ID() byte
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

type ClientAuthenticationChannels struct {
	Data           chan []byte
	FirstAuthReply chan *message.AuthenticationReply
	FinalAuthReply chan *message.AuthenticationReply
	Error          chan error
}

func NewClientAuthenticationChannels() *ClientAuthenticationChannels {
	return &ClientAuthenticationChannels{
		Data:           make(chan []byte, 1),
		FirstAuthReply: make(chan *message.AuthenticationReply, 1),
		FinalAuthReply: make(chan *message.AuthenticationReply, 1),
		Error:          make(chan error, 1),
	}
}

type ClientAuthenticationMethod interface {
	Authenticate(
		ctx context.Context,
		conn net.Conn,
		cac ClientAuthenticationChannels,
	) (*message.AuthenticationReply, error)
	ID() byte
}
