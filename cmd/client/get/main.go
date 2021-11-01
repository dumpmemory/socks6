package main

import (
	"net/http"
	"os"

	"github.com/studentmain/socks6"
)

func main() {
	sc := socks6.Client{
		Server:    "127.0.0.1:10888",
		Encrypted: false,
	}
	ht := http.Transport{
		Dial: sc.Dial,
	}
	c := http.Client{
		Transport: &ht,
	}
	ex, err := c.Get("http://example.com")
	if err != nil {
		panic(err)
	}
	ex.Write(os.Stdout)
}
