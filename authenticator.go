package socks6

import (
	"github.com/studentmain/socks6/message"
)

// client's name, for logging etc
type ClientID string

type Authenticator interface {
	Authenticate(req message.Request) (AuthenticationResult, message.AuthenticationReply)
}

type AuthenticationResult struct {
	Success        bool
	SelectedMethod byte
	ClientID       ClientID
	SessionID      []byte
}

type NullAuthenticator struct{}

func (n NullAuthenticator) Authenticate(req message.Request) (AuthenticationResult, message.AuthenticationReply) {
	result := AuthenticationResult{
		Success:        true,
		SelectedMethod: 0,
	}
	reply := message.AuthenticationReply{
		Type: message.AuthenticationReplySuccess,
	}
	return result, reply
}
