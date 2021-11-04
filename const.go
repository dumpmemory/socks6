// socks6 implements SOCKS protocol version 6 client and server
package socks6

import "github.com/studentmain/socks6/message"

const (
	SocksCleartextPort = 1080
	// TODO: waiting for IANA consideration
	SocksEncryptedPort = 8389
)

const Version = message.ProtocolVersion
