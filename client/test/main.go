package main

import (
	"github.com/studentmain/socks6/client"
	"github.com/studentmain/socks6/internal/lg"
)

func main() {
	c := client.Client{
		ProxyHost:     "127.0.0.1",
		CleartextPort: 10888,
		//EncryptedPort: 10889,
	}
	conn, err := c.Dial("tcp", "127.0.0.1:32768")
	if err != nil {
		lg.Fatal(err)
	}
	_, err = conn.Write([]byte{1, 2, 3, 4, 5, 6})
	if err != nil {
		lg.Fatal(err)
	}
}
