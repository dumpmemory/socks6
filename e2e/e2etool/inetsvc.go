package e2etool

import (
	"context"
	"io"
	"net"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
)

func Echo(c io.ReadWriteCloser) {
	b := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(b)
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

func ServeTCP(ctx context.Context, addr string, f func(io.ReadWriteCloser)) {
	s := internal.Must2(net.Listen("tcp", addr))
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
