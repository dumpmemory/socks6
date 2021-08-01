package main

import (
	"time"

	"github.com/studentmain/socks6/server"
)

func main() {
	s := server.Server{
		CleartextPort: 10888,
		EncryptedPort: 10889,
		Address:       "0.0.0.0",
	}
	s.Start()
	time.Sleep(1 * time.Hour)
}
