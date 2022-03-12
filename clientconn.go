package socks6

import (
	"net"

	"github.com/studentmain/socks6/message"
)

// ClientConn represents a SOCKS 6 connection received by server
type ClientConn struct {
	Conn    net.Conn         // base connection
	Request *message.Request // request sent by client

	ClientId string // client identifier provided by authenticator
	Session  []byte // the session this connection belongs to

	InitialData []byte // client's initial data
}

// Destination is endpoint included in client's request
func (c ClientConn) Destination() *message.Socks6Addr {
	return c.Request.Endpoint
}

// ConnId return connection's client endpoint string for logging purpose
func (c ClientConn) ConnId() string {
	return conn3Tuple(c.Conn)
}

// WriteReplyCode see WriteReply
func (c ClientConn) WriteReplyCode(code message.ReplyCode) error {
	return c.WriteReply(code, message.DefaultAddr, message.NewOptionSet())
}

// WriteReplyAddr see WriteReply
func (c ClientConn) WriteReplyAddr(code message.ReplyCode, ep net.Addr) error {
	return c.WriteReply(code, ep, message.NewOptionSet())
}

// WriteReply write operation reply with given parameter to client
func (c ClientConn) WriteReply(code message.ReplyCode, ep net.Addr, opt *message.OptionSet) error {
	oprep := message.NewOperationReplyWithCode(code)
	oprep.Endpoint = message.ConvertAddr(ep)
	oprep.Options = opt
	setSessionId(oprep, c.Session)
	_, e := c.Conn.Write(oprep.Marshal())
	return e
}
