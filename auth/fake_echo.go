package auth

import (
	"context"
	"crypto/rand"
	"io"
	"net"
)

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
