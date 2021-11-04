package main

import (
	"context"
	"net"

	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/cmd/ssocks6"
)

func main() {
	sw := socks6.NewServerWorker()

	l, err := net.Listen("tcp", "127.0.0.1:8388")
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			panic(err)
		}
		sc := ssocks6.NewSSConn(c, "aes-256-gcm", []byte("123456"))
		go sw.ServeStream(context.Background(), sc)
	}
}
