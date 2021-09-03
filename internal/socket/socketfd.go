package socket

import (
	"context"
	"errors"
	"log"
	"net"
	"syscall"

	"github.com/studentmain/socks6/message"
)

const ip_df = 14

func connFd(conn net.Conn) (uintptr, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, errors.New("not tcp conn")
	}
	file, err := tc.File()
	if err != nil {
		return 0, err
	}
	return file.Fd(), nil
}

func setsockoptBtoi(b bool) int {
	val := 0
	if b {
		val = 1
	}
	return val
}

func SetConnOpt(conn net.Conn, opt message.StackOptionInfo) message.StackOptionInfo {
	fd, err := connFd(conn)
	if err != nil {
		log.Print(err)
		return nil
	}
	return applyIPOption(fd, opt)
}

func DialWithOption(ctx context.Context, addr message.Socks6Addr, opt message.StackOptionInfo) (net.Conn, message.StackOptionInfo, error) {
	appliedOption := message.StackOptionInfo{}

	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ipOpt := applyIPOption(fd, opt)
				appliedOption.Combine(ipOpt)
			})
		},
	}

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

	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ipOpt := applyIPOption(fd, opt)
				appliedOption.Combine(ipOpt)
			})
		},
	}

	listener, err := cfg.Listen(ctx, "tcp", addr.String())
	return listener, appliedOption, err
}
