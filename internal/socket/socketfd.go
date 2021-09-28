package socket

import (
	"context"
	"net"

	"github.com/studentmain/socks6/message"
)

func SetConnOpt(conn net.Conn, opt message.StackOptionInfo) message.StackOptionInfo {
	return message.StackOptionInfo{}
}

func DialWithOption(ctx context.Context, addr message.Socks6Addr, opt message.StackOptionInfo) (net.Conn, message.StackOptionInfo, error) {
	appliedOption := message.StackOptionInfo{}

	dialer := net.Dialer{}

	happyEyeballOp, ok := opt[message.StackOptionIPHappyEyeball]
	if ok && addr.AddressType == message.AddressTypeDomainName {
		if happyEyeballOp.(bool) {
			appliedOption[message.StackOptionIPHappyEyeball] = true
		} else {
			dialer.FallbackDelay = -1
			appliedOption[message.StackOptionIPHappyEyeball] = false
		}
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr.String())
	return conn, appliedOption, err
}

func ListenerWithOption(ctx context.Context, addr message.Socks6Addr, opt message.StackOptionInfo) (net.Listener, message.StackOptionInfo, error) {
	appliedOption := message.StackOptionInfo{}

	cfg := net.ListenConfig{}

	listener, err := cfg.Listen(ctx, "tcp", addr.String())
	return listener, appliedOption, err
}
