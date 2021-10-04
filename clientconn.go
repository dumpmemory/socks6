package socks6

import (
	"net"

	"github.com/studentmain/socks6/message"
)

type ClientConn struct {
	Conn    net.Conn
	Request *message.Request

	ClientId string // client identifier provided by authn
	Session  []byte

	InitialData []byte
}

func (c ClientConn) Destination() *message.Socks6Addr {
	return c.Request.Endpoint
}

func (c ClientConn) ConnId() string {
	return conn3Tuple(c.Conn)
}

func (c ClientConn) WriteReplyCode(code message.ReplyCode) error {
	return c.WriteReply(code, message.ParseAddr(":0"), message.NewOptionSet())
}

func (c ClientConn) WriteReplyAddr(code message.ReplyCode, ep net.Addr) error {
	return c.WriteReply(code, ep, message.NewOptionSet())
}

func (c ClientConn) WriteReply(code message.ReplyCode, ep net.Addr, opt *message.OptionSet) error {
	oprep := message.NewOperationReplyWithCode(code)
	oprep.Endpoint = message.ParseAddr(ep.String())
	oprep.Options = opt
	setSessionId(oprep, c.Session)
	_, e := c.Conn.Write(oprep.Marshal())
	return e
}
