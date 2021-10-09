package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/lg"
	"github.com/studentmain/socks6/message"
)

type Client struct {
	ProxyHost     string
	EncryptedPort uint16
	CleartextPort uint16

	UDPOverTCP             bool
	Dialer                 net.Dialer
	AuthenticationMethod   auth.ClientAuthenticationMethod
	AuthenticationMethodId byte

	UseSession bool
	UseToken   uint32
	Backlog    int

	session  []byte
	token    uint32
	maxToken uint32
}

func (c *Client) Dial(network string, addr string) (net.Conn, error) {
	return c.DialWithOption(network, addr, nil, nil)
}

func (c *Client) DialWithOption(network string, addr string, initData []byte, option *message.OptionSet) (net.Conn, error) {
	sconn, opr, err := c.handshake(context.TODO(), message.CommandConnect, addr, initData, option)
	if err != nil {
		return nil, err
	}
	return &TCPConnectClient{
		base:   sconn,
		remote: message.ParseAddr(addr),
		rbind:  opr.Endpoint,
	}, nil
}

func (c *Client) Listen(network string, addr string) (net.Listener, error) {
	return nil, nil
}

func (c *Client) ListenUDP(network string, addr string) (net.PacketConn, error) {
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
	uc := UDPClient{
		uot:   c.UDPOverTCP,
		rbind: opr.Endpoint,
	}

	u1, err := message.ParseUDPHeaderFrom(sconn)
	if err != nil {
		return nil, err
	}
	uc.assocId = u1.AssociationID

	if uc.uot {
		uc.base = sconn
	} else {
		uc.assocOk = true
		go func() {
			for {
				rb := make([]byte, 256)
				_, err := sconn.Read(rb)
				if err != nil {
					uc.assocOk = false
				}
			}
		}()
		uc.base, err = c.makeDGramConn()
		if err != nil {
			return nil, err
		}
	}

	return &uc, nil
}

func (c *Client) Test() error {
	sconn, _, err := c.handshake(context.TODO(), message.CommandNoop, ":0", []byte{}, nil)
	if err != nil {
		return err
	}
	sconn.Close()
	return nil
}

func (c *Client) makeStreamConn() (net.Conn, error) {
	var nc net.Conn
	if c.EncryptedPort != 0 {
		lg.Debug("connect via tls")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.EncryptedPort), 10))
		conn, err := c.Dialer.Dial("tcp", addr)
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
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.CleartextPort), 10))
		pc, err := c.Dialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		nc = pc
	}

	return nc, nil
}

func (c *Client) makeDGramConn() (net.Conn, error) {
	var nc net.Conn
	if c.EncryptedPort != 0 {
		lg.Debug("connect via dtls")
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.EncryptedPort), 10))
		conn, err := c.Dialer.Dial("udp", addr)
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
		addr := net.JoinHostPort(c.ProxyHost, strconv.FormatInt(int64(c.CleartextPort), 10))
		pc, err := c.Dialer.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
		nc = pc
	}
	return nc, nil
}

func (c *Client) bind(conn net.Conn, isAccept bool) error {
	//todo
	return nil
}

func (c *Client) authn(req message.Request, sconn net.Conn, initData []byte) error {
	var cac *auth.ClientAuthenticationChannels
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
		ld := len(initData)
		if ld > 0 || c.AuthenticationMethodId != 0 {
			req.Options.Add(message.Option{
				Kind: message.OptionKindAuthenticationMethodAdvertisement,
				Data: message.AuthenticationMethodAdvertisementOptionData{
					InitialDataLength: uint16(ld),
					Methods:           []byte{c.AuthenticationMethodId},
				},
			})
		}
		if c.AuthenticationMethodId != 0 {
			cac = auth.NewClientAuthenticationChannels()
			go c.AuthenticationMethod.Authenticate(context.TODO(), sconn, *cac)
			data := <-cac.Data
			if len(data) > 0 {
				req.Options.Add(message.Option{Kind: message.OptionKindAuthenticationData, Data: message.AuthenticationDataOptionData{
					Method: c.AuthenticationMethodId,
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

	_, err := sconn.Write(req.Marshal())
	if err != nil {
		return err
	}
	// todo auth
	aurep1, err := message.ParseAuthenticationReplyFrom(sconn)
	if err != nil {
		return err
	}
	var finalRep *message.AuthenticationReply

	// authn finished
	if aurep1.Type == message.AuthenticationReplySuccess {
		finalRep = aurep1
	} else {
		if d, s := aurep1.Options.GetData(message.OptionKindAuthenticationMethodSelection); !s {
			finalRep = aurep1
		} else if d.(message.AuthenticationMethodSelectionOptionData).Method != c.AuthenticationMethodId {
			finalRep = aurep1
		}
	}

	if finalRep == nil && cac == nil {
		return errors.New("server wants 2 stage authn")
	}
	if cac != nil {
		cac.FirstAuthReply <- finalRep
		err := <-cac.Error
		finalRep = <-cac.FinalAuthReply
		if err != nil {
			return err
		}
	}

	if finalRep.Type != message.AuthenticationReplySuccess {
		return errors.New("authn fail")
	}
	if _, f := finalRep.Options.GetData(message.OptionKindSessionInvalid); f {
		c.session = []byte{}
		return errors.New("session fail")
	}
	if _, f := finalRep.Options.GetData(message.OptionKindIdempotenceRejected); f {
		c.maxToken = 0
		return errors.New("token fail")
	}
	if c.UseSession {
		if _, f := finalRep.Options.GetData(message.OptionKindSessionOK); !f {
			return errors.New("session fail")
		}

		if c.UseToken > 0 {
			if _, f := finalRep.Options.GetData(message.OptionKindIdempotenceAccepted); !f {
				return errors.New("token fail")
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

func (c *Client) handshake(
	ctx context.Context,
	op message.CommandCode,
	addr string,
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
		Endpoint:    message.ParseAddr(addr),
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
