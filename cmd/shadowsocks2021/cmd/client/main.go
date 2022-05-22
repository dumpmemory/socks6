package main

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/cmd/shadowsocks2021"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
	"github.com/txthinking/socks5"
)

type hhh struct {
	c socks6.Client
}

func (h hhh) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	reqAddr := message.ParseAddr(r.Address())

	opset := message.NewOptionSet()
	opset.Add(message.Option{
		Kind: shadowsocks2021.OptionKindSSTick,
		Data: shadowsocks2021.SSTickOptionData{
			Time: time.Now(),
		},
	})
	opset.Add(message.Option{
		Kind: shadowsocks2021.OptionKindSSPadding,
		Data: &shadowsocks2021.SSPaddingOptionData{
			RawOptionData: message.RawOptionData{
				Data: make([]byte, internal.RandUint16()%256),
			},
		},
	})

	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return err
		}
		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())
		io.Copy(ioutil.Discard, c)
		return nil
	}
	if r.Cmd == socks5.CmdBind {

		l, err := h.c.BindRequest(context.Background(), reqAddr, opset)
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
	c2, err := h.c.ConnectRequest(context.Background(), reqAddr, nil, opset)
	if err != nil {
		return err
	}
	defer c2.Close()
	return shadowsocks2021.Relay(c2, c)
}

type udpxchg struct {
	ClientAddr *net.UDPAddr
	RemoteConn *socks6.ProxyUDPConn
}

func (u udpxchg) senddgram(d socks5.Datagram) error {
	addr := message.ParseAddr(d.Address())
	data := d.Data

	_, err := u.RemoteConn.WriteTo(data, addr)
	return err
}

func (h hhh) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	src := addr.String()
	var ch chan byte

	dst := d.Address()
	var ue *udpxchg
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*udpxchg)
		return ue.senddgram(*d)
	}

	var laddr *net.UDPAddr
	any, ok := s.UDPSrc.Get(src + dst)
	if ok {
		laddr = any.(*net.UDPAddr)
	}
	raddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return err
	}
	rc, err := h.c.UDPAssociateRequest(context.Background(), raddr, nil)
	if err != nil {
		return err
	}
	if laddr == nil {
		s.UDPSrc.Set(src+dst, rc.LocalAddr().(*net.UDPAddr), -1)
	}
	ue = &udpxchg{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	if err := ue.senddgram(*d); err != nil {
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)
	go func(ue *udpxchg, dst string) {
		defer func() {
			ue.RemoteConn.Close()
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()
		var b [65507]byte
		for {
			select {
			case <-ch:
				return
			default:
				if s.UDPTimeout != 0 {
					if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
						log.Println(err)
						return
					}
				}
				n, raddr, err := ue.RemoteConn.ReadFrom(b[:])
				if err != nil {
					return
				}

				a, addr, port, err := socks5.ParseAddress(raddr.String())
				if err != nil {
					log.Println(err)
					return
				}
				d1 := socks5.NewDatagram(a, addr, port, b[0:n])
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					return
				}
			}
		}
	}(ue, dst)
	return nil
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
