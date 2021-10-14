package main

import (
	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/internal/lg"
	"github.com/studentmain/socks6/message"
)

func main() {
	c := socks6.Client{
		Server: "127.0.0.1:10888",
	}
	pc, err := c.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		lg.Fatal(err)
	}
	_, err = pc.WriteTo([]byte{1, 2, 3, 4, 5, 6}, message.ParseAddr("127.0.0.1:12345"))
	if err != nil {
		lg.Fatal(err)
	}
	buf := make([]byte, 256)
	l, r, err := pc.ReadFrom(buf)
	lg.Info(l, r, err, buf)
}
