package e2etool

import (
	"context"
	"io"
	"net"

	"github.com/studentmain/socks6/common/arrayx"
	"github.com/studentmain/socks6/common/errorh"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
)

func Echo(c io.ReadWriteCloser) {
	b := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(b)
	defer c.Close()
	for {
		n, err := c.Read(b)
		if err != nil {
			return
		}
		_, err = c.Write(b[:n])
		if err != nil {
			return
		}
	}
}

func UEcho(p net.PacketConn, d []byte, a net.Addr) {
	p.WriteTo(d, a)
}

func Discard(c io.ReadWriteCloser) {
	b := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(b)
	defer c.Close()
	for {
		_, err := c.Read(b)
		if err != nil {
			return
		}
	}
}
func UDiscard(p net.PacketConn, d []byte, a net.Addr) {
}

func Chargen(c io.ReadWriteCloser) {
	b := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(b)
	defer c.Close()
	for {
		_, err := c.Write(b)
		if err != nil {
			return
		}
	}
}
func UChargen(p net.PacketConn, d []byte, a net.Addr) {
	b := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(b)
	p.WriteTo(b, a)
}

func ServeTCP(ctx context.Context, addr string, f func(io.ReadWriteCloser)) {
	s := errorh.Must2(net.Listen("tcp", addr))
	defer s.Close()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		fd, err := s.Accept()
		if err != nil {
			lg.Info("stop e2etool server", err)
			return
		}
		go f(fd)
	}
}

func ServeUDP(ctx context.Context, addr string, f func(p net.PacketConn, d []byte, a net.Addr)) {
	s := errorh.Must2(net.ListenPacket("udp", addr))
	defer s.Close()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.ReadFrom(buf)
		data := arrayx.Dup(buf[:n])
		if err != nil {
			lg.Info("stop e2etool server", err)
			return
		}
		go f(s, data, addr)
	}
}
