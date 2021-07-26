package main

import (
	"time"

	"github.com/studentmain/socks6/server"
)

func main() {
	s := server.Server{}
	s.Start()
	time.Sleep(1 * time.Hour)
}
