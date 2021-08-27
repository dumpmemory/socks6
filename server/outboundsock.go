package server

import (
	"context"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/studentmain/socks6"
)

func makeDestConn(req socks6.Request) (net.Conn, StackOptionInfo, error) {
	rso := GetStackOptionInfo(req.Options, false)
	supported := StackOptionInfo{}

	d := net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(
				func(fd uintptr) {
					supported = setsocks6optTcpClient(fd, rso)
				})
			return nil
		},
	}
	happyEyeballI, happyEyeballOk := rso[socks6.StackOptionIPHappyEyeball]
	if happyEyeballOk && socks6.AddressType(req.Endpoint.AddressType) == socks6.AddressTypeDomainName {
		happyEyeball := happyEyeballI.(bool)
		if !happyEyeball {
			// rfc8305 is based on rfc6555
			d.FallbackDelay = -1
			supported[socks6.StackOptionIPHappyEyeball] = false
		} else {
			supported[socks6.StackOptionIPHappyEyeball] = true
		}
	}
	c, e := d.Dial("tcp", req.Endpoint.String())
	return c, supported, e
}

func makeDestListener(req socks6.Request) (net.Listener, StackOptionInfo, error) {
	rso := GetStackOptionInfo(req.Options, false)

	supported := StackOptionInfo{}
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(
				func(fd uintptr) {
					supported = setsocks6optTcpServer(fd, rso)
				})
			return nil
		},
	}
	l, err := cfg.Listen(context.Background(), "tcp", req.Endpoint.String())
	return l, supported, err
}

func makeDestUDP(req socks6.Request) (*net.UDPConn, StackOptionInfo, error) {
	ep := req.Endpoint.String()
	addr, err := net.ResolveUDPAddr("udp", ep)
	op := StackOptionInfo{}
	if err != nil {
		log.Print(err)
		return nil, op, err
	}
	// todo mcast?
	uc, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Print(err)
		return nil, op, err
	}

	rso := GetStackOptionInfo(req.Options, false)
	op = prepareDestUDP(uc, rso)
	return uc, op, nil
}

func prepareDestUDP(conn *net.UDPConn, opt StackOptionInfo) StackOptionInfo {
	raw, _ := conn.SyscallConn()
	op := StackOptionInfo{}

	raw.Control(
		func(fd uintptr) {
			op = setsocks6optUdp(fd, opt)
		})
	return op
}
