package socks6

import (
	"net"

	"github.com/studentmain/socks6/common/nt"
	"github.com/studentmain/socks6/message"
)

// SocksConn represents a SOCKS 6 connection received by server
type SocksConn struct {
	Conn    net.Conn
	MuxConn nt.MultiplexedConn
	Request *message.Request // request sent by client

	ClientId    string // client identifier provided by authenticator
	Session     []byte // the session this connection belongs to
	StreamId    uint32 // stream id provided by client
	InitialData []byte // client's initial data
}

// Destination is endpoint included in client's request
func (c SocksConn) Destination() *message.SocksAddr {
	return c.Request.Endpoint
}

// ConnId return connection's client endpoint string for logging purpose
func (c SocksConn) ConnId() string {
	return conn3Tuple(c.Conn)
}

// WriteReplyCode see WriteReply
func (c SocksConn) WriteReplyCode(code message.ReplyCode) error {
	return c.WriteReply(code, message.DefaultAddr, message.NewOptionSet())
}

// WriteReplyAddr see WriteReply
func (c SocksConn) WriteReplyAddr(code message.ReplyCode, ep net.Addr) error {
	return c.WriteReply(code, ep, message.NewOptionSet())
}

// WriteReply write operation reply with given parameter to client
func (c SocksConn) WriteReply(code message.ReplyCode, ep net.Addr, opt *message.OptionSet) error {
	oprep := message.NewOperationReplyWithCode(code)
	oprep.Endpoint = message.ConvertAddr(ep)
	oprep.Options = opt
	c.setSessionId(oprep)
	c.setStreamId(oprep)
	_, e := c.Conn.Write(oprep.Marshal())
	return e
}

// setSessionId append session id option to operation reply when id is not null
func (c SocksConn) setSessionId(oprep *message.OperationReply) *message.OperationReply {
	if c.Session == nil {
		return oprep
	}
	oprep.Options.Add(message.Option{
		Kind: message.OptionKindSessionID,
		Data: message.SessionIDOptionData{
			ID: c.Session,
		},
	})
	return oprep
}

func (c SocksConn) setStreamId(oprep *message.OperationReply) *message.OperationReply {
	if c.MuxConn == nil {
		return oprep
	}
	oprep.Options.Add(message.Option{
		Kind: message.OptionKindStreamID,
		Data: message.StreamIDOptionData{
			ID: c.StreamId,
		},
	})
	return oprep
}
