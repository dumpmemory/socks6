package socks6

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/message"
)

// Client is a SOCKS 6 client, implements net.Dialer, net.Listener
type Client struct {
	// server address
	Server string
	// use TLS and DTLS when connect to server
	Encrypted bool
	// send datagram over TCP
	UDPOverTCP bool
	// function to create underlying connection, net.Dial will used when it is nil
	DialFunc func(network string, addr string) (net.Conn, error)
	// authentication method to be used, can be nil
	AuthenticationMethod auth.ClientAuthenticationMethod

	// should client request session
	UseSession bool
	// how much token will requested
	UseToken uint32
	// suggested bind backlog
	Backlog int

	session  []byte
	token    uint32
	maxToken uint32
}

// impl

func (c *Client) Dial(network string, addr string) (net.Conn, error) {
	if network[:3] == "udp" {
		a, e := c.UDPAssociateRequest(message.ParseAddr(addr), nil)
		if e != nil {
			return nil, e
		}
		a.expectAddr = message.ParseAddr(addr)
		return a, nil
	}
	return c.ConnectRequest(addr, nil, nil)
}

func (c *Client) Listen(network string, addr string) (net.Listener, error) {
	return c.BindRequest(message.ParseAddr(addr), nil)
}

func (c *Client) ListenPacket(network string, addr string) (net.PacketConn, error) {
	return c.UDPAssociateRequest(message.ParseAddr(addr), nil)
}

// raw requests

func (c *Client) ConnectRequest(addr string, initData []byte, option *message.OptionSet) (net.Conn, error) {
	addr2 := message.ParseAddr(addr)
	sconn, opr, err := c.handshake(context.TODO(), message.CommandConnect, addr2, initData, option)
	if err != nil {
		return nil, err
	}
	return &ProxyTCPConn{
		netConn: sconn,
		addrPair: addrPair{
			local:  opr.Endpoint,
			remote: addr2,
		},
	}, nil
}

func (c *Client) BindRequest(addr net.Addr, option *message.OptionSet) (*ProxyTCPListener, error) {
	sconn, opr, err := c.handshake(context.TODO(), message.CommandBind, addr, []byte{}, option)
	if err != nil {
		return nil, err
	}
	rso := message.GetStackOptionInfo(opr.Options, false)
	bl := uint16(0)
	if ibl, ok := rso[message.StackOptionTCPBacklog]; ok {
		bl = ibl.(uint16)
	}

	return &ProxyTCPListener{
		netConn: sconn,
		backlog: bl,
		bind:    opr.Endpoint,
		client:  c,
		used:    false,
		op:      option,
	}, nil
}

func (c *Client) UDPAssociateRequest(addr net.Addr, option *message.OptionSet) (*ProxyUDPConn, error) {
	sconn, opr, err := c.handshake(
		context.TODO(),
		message.CommandUdpAssociate,
		addr,
		[]byte{},
		nil,
	)
	if err != nil {
		return nil, err
	}
	uc := ProxyUDPConn{
		overTcp: c.UDPOverTCP,
		base:    sconn,
		rbind:   opr.Endpoint,
	}
	if uc.overTcp {
		uc.conn = uc.base
	} else {
		dc, err := c.makeDGramConn()
		if err != nil {
			return nil, err
		}
		uc.conn = dc
	}
	uc.init()
	return &uc, nil
}

// NoopRequest send a NOOP request
func (c *Client) NoopRequest() error {
	sconn, _, err := c.handshake(context.TODO(), message.CommandNoop, message.DefaultAddr, []byte{}, nil)
	if err != nil {
		return err
	}
	sconn.Close()
	return nil
}

// common

func (c *Client) makeStreamConn() (net.Conn, error) {
	var nc net.Conn
	df := net.Dial
	if c.DialFunc != nil {
		df = c.DialFunc
	}
	if c.Encrypted {
		lg.Debug("connect via tls")
		conn, err := net.Dial("tcp", c.Server)
		if err != nil {
			return nil, err
		}
		pc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		nc = pc
	} else {
		lg.Debug("connect via tcp")
		pc, err := df("tcp", c.Server)
		if err != nil {
			return nil, err
		}
		nc = pc
	}

	return nc, nil
}

func (c *Client) makeDGramConn() (net.Conn, error) {
	var nc net.Conn
	df := net.Dial
	if c.DialFunc != nil {
		df = c.DialFunc
	}
	if c.Encrypted {
		lg.Debug("connect via dtls")
		conn, err := net.Dial("udp", c.Server)
		if err != nil {
			return nil, err
		}
		pc, err := dtls.Client(conn, &dtls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, err
		}
		nc = pc
	} else {
		lg.Debug("connect via udp")
		pc, err := df("udp", c.Server)
		if err != nil {
			return nil, err
		}
		nc = pc
	}
	return nc, nil
}

// authn running authentication in handshake
func (c *Client) authn(req message.Request, sconn net.Conn, initData []byte) error {
	var cac *auth.ClientAuthenticationChannels
	if c.AuthenticationMethod == nil {
		c.AuthenticationMethod = auth.NoneClientAuthenticationMethod{}
	}
	// add authn options
	id := c.AuthenticationMethod.ID()
	if len(c.session) > 0 {
		// use session
		req.Options.Add(message.Option{Kind: message.OptionKindSessionID, Data: message.SessionIDOptionData{ID: c.session}})
		if c.maxToken-c.token > 0 {
			// use token
			req.Options.Add(message.Option{Kind: message.OptionKindIdempotenceExpenditure, Data: message.IdempotenceExpenditureOptionData{Token: c.token}})
			c.token++
			// request token when necessary
			if c.maxToken-c.token < c.UseToken/8 {
				req.Options.Add(message.Option{Kind: message.OptionKindTokenRequest, Data: message.TokenRequestOptionData{WindowSize: c.UseToken}})
			}
		}
	} else {
		// use original authn method
		ld := len(initData)
		if ld > 0 || id != 0 {
			req.Options.Add(message.Option{
				Kind: message.OptionKindAuthenticationMethodAdvertisement,
				Data: message.AuthenticationMethodAdvertisementOptionData{
					InitialDataLength: uint16(ld),
					Methods:           []byte{id},
				},
			})
		}
		if id != 0 {
			cac = auth.NewClientAuthenticationChannels()
			go c.AuthenticationMethod.Authenticate(context.TODO(), sconn, *cac)
			data := <-cac.Data
			if len(data) > 0 {
				req.Options.Add(message.Option{Kind: message.OptionKindAuthenticationData, Data: message.AuthenticationDataOptionData{
					Method: id,
					Data:   data,
				}})
			}
		}

		// request session and token
		if c.UseSession {
			req.Options.Add(message.Option{Kind: message.OptionKindSessionRequest, Data: message.SessionRequestOptionData{}})
			if c.UseToken != 0 {
				req.Options.Add(message.Option{Kind: message.OptionKindTokenRequest, Data: message.TokenRequestOptionData{WindowSize: c.UseToken}})
			}
		}
	}

	// io
	if _, err := sconn.Write(req.Marshal()); err != nil {
		return err
	}
	aurep1, err := message.ParseAuthenticationReplyFrom(sconn)
	if err != nil {
		return err
	}
	var finalRep *message.AuthenticationReply

	if aurep1.Type == message.AuthenticationReplySuccess {
		// success at stage 1
		finalRep = aurep1
	} else {
		if d, s := aurep1.Options.GetData(message.OptionKindAuthenticationMethodSelection); !s {
			// can't continue
			finalRep = aurep1
		} else if d.(message.AuthenticationMethodSelectionOptionData).Method != id {
			// continue with different method, unsupported
			finalRep = aurep1
		}
	}

	if finalRep == nil && cac == nil {
		// need stage 2, but authn channel not exist
		return errors.New("server wants 2 stage authn")
	}
	if cac != nil {
		// write 1st reply
		cac.FirstAuthReply <- finalRep
		// read error and reply
		err := <-cac.Error
		finalRep = <-cac.FinalAuthReply
		if err != nil {
			return err
		}
	}

	// check final reply
	fail := false
	if finalRep.Type != message.AuthenticationReplySuccess {
		fail = true
	}
	if _, f := finalRep.Options.GetData(message.OptionKindSessionInvalid); f {
		c.session = []byte{}
		fail = true
	}
	if _, f := finalRep.Options.GetData(message.OptionKindIdempotenceRejected); f {
		c.maxToken = 0
		fail = true
	}
	if fail {
		return errors.New("authn fail")
	}
	if c.UseSession {
		if _, f := finalRep.Options.GetData(message.OptionKindSessionOK); !f {
			// no session is not really a problem
			return nil
		}

		if c.UseToken > 0 {
			if _, f := finalRep.Options.GetData(message.OptionKindIdempotenceAccepted); !f {
				return nil
			}
			if d, ok := finalRep.Options.GetData(message.OptionKindIdempotenceWindow); ok {
				dd := d.(message.IdempotenceWindowOptionData)
				c.token = dd.WindowBase
				c.maxToken = dd.WindowSize
			} else {
				if c.maxToken == 0 {
					return errors.New("token fail")
				}
			}
		}
	}
	return nil
}

// handshake handle the common handshake part of protocol
func (c *Client) handshake(
	ctx context.Context,
	op message.CommandCode,
	addr net.Addr,
	initData []byte,
	option *message.OptionSet,
) (net.Conn, *message.OperationReply, error) {
	sconn, err := c.makeStreamConn()
	if err != nil {
		return nil, nil, err
	}
	cd := internal.NewCancellableDefer(func() {
		sconn.Close()
	})
	defer cd.Defer()

	if option == nil {
		option = message.NewOptionSet()
	}
	req := message.Request{
		CommandCode: op,
		Endpoint:    message.ConvertAddr(addr),
		Options:     option,
	}

	if err := c.authn(req, sconn, initData); err != nil {
		return nil, nil, err
	}

	opr, err := message.ParseOperationReplyFrom(sconn)
	if err != nil {
		return nil, nil, err
	}
	if opr.ReplyCode != 0 {
		return nil, nil, errors.New("operation reply fail")
	}
	if c.UseSession {
		if d, ok := opr.Options.GetData(message.OptionKindSessionID); ok {
			c.session = d.(message.SessionIDOptionData).ID
		} else {
			if len(c.session) == 0 {
				return nil, nil, errors.New("session fail")
			}
		}
	}

	cd.Cancel()
	return sconn, opr, nil
}
