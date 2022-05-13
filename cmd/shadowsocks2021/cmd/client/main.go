package main

import (
	"net"

	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/cmd/shadowsocks2021"
	"github.com/txthinking/socks5"
)

type hhh struct {
	c socks6.Client
}

func (h hhh) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdBind {
		l, err := h.c.Listen("tcp", r.Address())
		if err != nil {
			return err
		}
		defer l.Close()
		c2, err := l.Accept()
		if err != nil {
			return err
		}
		defer c2.Close()
		return shadowsocks2021.Relay(c2, c)
	}
	c2, err := h.c.Dial("tcp", r.Address())
	if err != nil {
		return err
	}
	defer c2.Close()
	return shadowsocks2021.Relay(c2, c)
}
func (h hhh) UDPHandle(s *socks5.Server, c *net.UDPAddr, r *socks5.Datagram) error {
	return socks5.ErrUnsupportCmd
}

func ssdial(network string, addr string) (net.Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	sc := shadowsocks2021.NewSSConn(c, []byte("123456"))
	return sc, nil
}

func main() {
	c := socks6.Client{
		Server:   "127.0.0.1:8388",
		DialFunc: ssdial,
	}
	s, err := socks5.NewClassicServer("127.0.0.1:10898", "127.0.0.1", "", "", 5, 5)
	if err != nil {
		panic(err)
	}
	s.ListenAndServe(hhh{c: c})
}
