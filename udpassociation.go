package socks6

import (
	"net"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

type udpAssociation struct {
	id  uint64
	udp net.PacketConn

	cc          ClientConn
	acceptTcp   bool
	acceptDgram string

	pair string
}

func newUdpAssociation(cc ClientConn, udp net.PacketConn, pair net.Addr) *udpAssociation {
	id := internal.RandUint64()
	return &udpAssociation{
		id:  id,
		udp: udp,

		cc:          cc,
		acceptTcp:   true,
		acceptDgram: "",
		pair:        message.AddrString(pair),
	}
}
