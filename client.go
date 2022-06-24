package socks6

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/lucas-clemente/quic-go"
	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/common/nt"
	"github.com/studentmain/socks6/message"
)

// Client is a SOCKS 6 client, implements net.Dialer, net.Listener
type Client struct {
	// server address
	Server string
	// use TLS and DTLS when connect to server
	Encrypted bool
	// use QUIC
	QUIC bool
	// send datagram over TCP, when use QUIC, send datagram over QUIC stream instead of QUIC datagram
	UDPOverTCP bool
	// function to create underlying connection, net.Dial will used when it is nil
	DialFunc func(ctx context.Context, network string, addr string) (net.Conn, error)
	// authentication method to be used, can be nil
	AuthenticationMethod auth.ClientAuthenticationMethod

	// should client request session
	UseSession bool
	// how much token will requested
	UseToken uint32
	// suggested bind backlog
	Backlog int

	EnableICMP bool

	session  []byte
	token    uint32
	maxToken uint32

	qc       nt.DualModeMultiplexedConn
	qudpconn common.SyncMap[uint64, *muxSeqPacket]
	qbind    common.SyncMap[uint32, *ProxyTCPListener]
	qsid     uint32
}

type muxSeqPacket struct {
	nt.SeqPacket
	ch  chan nt.Datagram
	err error
}

func (m *muxSeqPacket) NextDatagram() (nt.Datagram, error) {
	d, ok := <-m.ch
	if !ok {
		return nil, m.err
	}
	return d, nil
}

func (c *Client) muxAccept() {
	for {
		conn, err := c.qc.Accept()
		if err != nil {
			c.qc.Close()
			c.qc = nil
			return
		}
		buf := &bytes.Buffer{}
		r := io.TeeReader(conn, buf)

		rep, err := message.ParseOperationReplyFrom(r)
		if err != nil {
			continue
		}
		sidop, ok := rep.Options.GetData(message.OptionKindStreamID)
		if !ok {
			continue
		}
		sid := sidop.(message.StreamIDOptionData).ID
		ptl, ok := c.qbind.Load(sid)
		if !ok {
			continue
		}
		ptl.qch <- nt.NewBufferPrefixedConn(conn, buf.Bytes())
	}
}

func (c *Client) muxUdp() {
	for {
		d, err := c.qc.NextDatagram()
		if err != nil {
			c.qc.Close()
			c.qc = nil
			return
		}
		if len(d.Data()) < 12 {
			continue
		}
		id := binary.BigEndian.Uint64(d.Data()[4:])
		msp, ok := c.qudpconn.Load(id)
		if !ok {
			continue
		}
		msp.ch <- d
	}
}

// impl

func (c *Client) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	sa := message.ParseAddr(addr)
	if network[:3] == "udp" {
		la := message.AddrIPv4Zero
		if sa.AddressType == message.AddressTypeIPv6 {
			la = message.AddrIPv6Zero
		}
		a, e := c.UDPAssociateRequest(ctx, la, nil)
		if e != nil {
			return nil, e
		}
		a.expectAddr = sa
		return a, nil
	}
	return c.ConnectRequest(ctx, sa, nil, nil)
}

func (c *Client) Dial(network string, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

func (c *Client) ListenContext(ctx context.Context, network string, addr string) (net.Listener, error) {
	return c.BindRequest(ctx, message.ParseAddr(addr), nil)
}

func (c *Client) Listen(network string, addr string) (net.Listener, error) {
	return c.ListenContext(context.Background(), network, addr)
}

func (c *Client) ListenPacketContext(ctx context.Context, network string, addr string) (net.PacketConn, error) {
	return c.UDPAssociateRequest(ctx, message.ParseAddr(addr), nil)
}

func (c *Client) ListenPacket(network string, addr string) (net.PacketConn, error) {
	return c.ListenPacketContext(context.Background(), network, addr)
}

// raw requests

func (c *Client) ConnectRequest(ctx context.Context, addr net.Addr, initData []byte, option *message.OptionSet) (net.Conn, error) {
	sconn, opr, err := c.handshake(ctx, message.CommandConnect, addr, initData, option)
	if err != nil {
		return nil, err
	}
	return &ProxyTCPConn{
		netConn: sconn,
		addrPair: addrPair{
			local:  opr.Endpoint,
			remote: addr,
		},
	}, nil
}

func (c *Client) BindRequest(ctx context.Context, addr net.Addr, option *message.OptionSet) (*ProxyTCPListener, error) {
	if option == nil {
		option = message.NewOptionSet()
	}
	if c.Backlog > 0 {
		option.Add(message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelTCP,
				Code:      message.StackOptionCodeBacklog,
				Data: &message.BacklogOptionData{
					Backlog: uint16(c.Backlog),
				},
			},
		})
		// quic downstream, streamid
		if c.QUIC {
			option.Add(message.Option{
				Kind: message.OptionKindStreamID,
				Data: message.StreamIDOptionData{
					ID: c.qsid,
				},
			})
		}
	}

	sconn, opr, err := c.handshake(ctx, message.CommandBind, addr, []byte{}, option)
	if err != nil {
		return nil, err
	}
	rso := message.GetStackOptionInfo(opr.Options, false)
	backlog := uint16(0)
	if ibl, ok := rso[message.StackOptionTCPBacklog]; ok {
		backlog = ibl.(uint16)
	}
	ret := &ProxyTCPListener{
		netConn: sconn,
		backlog: backlog,
		bind:    opr.Endpoint,
		client:  c,
		used:    false,
		op:      option,
	}
	if c.QUIC && ret.backlog > 0 {
		ret.qch = make(chan net.Conn, ret.backlog)
		c.qbind.Store(c.qsid, ret)
		c.qsid++
	}
	return ret, nil
}

func (c *Client) UDPAssociateRequest(ctx context.Context, addr net.Addr, option *message.OptionSet) (*ProxyUDPConn, error) {
	opset := message.NewOptionSet()
	if c.EnableICMP {
		opset.Add(message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				RemoteLeg: true,
				Level:     message.StackOptionLevelUDP,
				Code:      message.StackOptionCodeUDPError,
				Data: &message.UDPErrorOptionData{
					Availability: true,
				},
			},
		})
	}

	sconn, opr, err := c.handshake(
		ctx,
		message.CommandUdpAssociate,
		addr,
		[]byte{},
		opset,
	)
	if err != nil {
		return nil, err
	}
	pconn := ProxyUDPConn{
		overTcp:  c.UDPOverTCP,
		origConn: sconn,
		rbind:    opr.Endpoint,
	}
	if pconn.overTcp {
		pconn.dataConn = nt.WrapNetConnUDP(pconn.origConn)
	} else {
		dconn, err2 := c.connectDatagram(ctx)
		if err2 != nil {
			return nil, &net.OpError{Op: "dial", Net: "socks6", Addr: addr, Err: err2}
		}
		pconn.dataConn = dconn
	}
	err = pconn.init()
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "socks6", Addr: addr, Source: pconn.LocalAddr(), Err: err}
	}
	return &pconn, nil
}

// NoopRequest send a NOOP request
func (c *Client) NoopRequest(ctx context.Context) error {
	sconn, _, err := c.handshake(ctx, message.CommandNoop, message.DefaultAddr, []byte{}, nil)
	if err != nil {
		return err
	}
	sconn.Close()
	return nil
}

// common

func (c *Client) getQuicConn(ctx context.Context, addr string) (nt.DualModeMultiplexedConn, error) {
	if c.qc == nil {
		q, err := quic.DialAddrEarlyContext(ctx, addr, &tls.Config{ServerName: c.Server}, nil)
		if err != nil {
			return nil, err
		}
		c.qc = nt.WrapQUICConn(q)
		go c.muxAccept()
		go c.muxUdp()
	}
	return c.qc, nil
}

func (c *Client) dialQuicT(ctx context.Context, network, address string) (net.Conn, error) {
	q, err := c.getQuicConn(ctx, address)
	if err != nil {
		return nil, err
	}
	return q.Dial()
}

func (c *Client) dialEncrypted(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: c.Server}}
		return d.DialContext(ctx, network, address)
	case "udp", "udp4", "udp6":
		a, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return dtls.DialWithContext(ctx, network, a, &dtls.Config{ServerName: c.Server})
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func (c *Client) connectStream(ctx context.Context) (net.Conn, error) {
	dial := (&net.Dialer{}).DialContext
	if c.DialFunc != nil {
		dial = c.DialFunc
	} else if c.QUIC {
		dial = c.dialQuicT
	} else if c.Encrypted {
		dial = c.dialEncrypted
	}

	conn, err := dial(ctx, "tcp", c.Server)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) connectDatagram(ctx context.Context) (nt.SeqPacket, error) {
	dial := (&net.Dialer{}).DialContext
	if c.DialFunc != nil {
		dial = c.DialFunc
	} else if c.QUIC {
		// only udp assoc can setup demux param (assoc id)
		return c.getQuicConn(ctx, c.Server)
	} else if c.Encrypted {
		dial = c.dialEncrypted
	}

	conn, err := dial(ctx, "udp", c.Server)
	if err != nil {
		return nil, err
	}
	return nt.WrapNetConnUDP(conn), nil
}

func (c *Client) createAuthnOption(ctx context.Context, sconn net.Conn, id byte, dataLen int) ([]message.Option, *auth.ClientAuthenticationChannels) {
	var cac *auth.ClientAuthenticationChannels
	opts := []message.Option{}
	if len(c.session) > 0 {
		// use session
		opts = append(opts, message.Option{Kind: message.OptionKindSessionID, Data: message.SessionIDOptionData{ID: c.session}})
		if c.maxToken-c.token > 0 {
			// use token
			opts = append(opts, message.Option{Kind: message.OptionKindIdempotenceExpenditure, Data: message.IdempotenceExpenditureOptionData{Token: c.token}})
			c.token++
			// request token when necessary
			if c.maxToken-c.token < c.UseToken/8 {
				opts = append(opts, message.Option{Kind: message.OptionKindTokenRequest, Data: message.TokenRequestOptionData{WindowSize: c.UseToken}})
			}
		}
	} else {
		// use original authn method
		if dataLen > 0 || id != 0 {
			opts = append(opts, message.Option{
				Kind: message.OptionKindAuthenticationMethodAdvertisement,
				Data: message.AuthenticationMethodAdvertisementOptionData{
					InitialDataLength: uint16(dataLen),
					Methods:           []byte{id},
				},
			})
		}
		if id != 0 {
			cac = auth.NewClientAuthenticationChannels()
			go c.AuthenticationMethod.Authenticate(ctx, sconn, *cac)
			data := <-cac.Data
			if len(data) > 0 {
				opts = append(opts, message.Option{Kind: message.OptionKindAuthenticationData, Data: message.AuthenticationDataOptionData{
					Method: id,
					Data:   data,
				}})
			}
		}

		// request session and token
		if c.UseSession {
			opts = append(opts, message.Option{Kind: message.OptionKindSessionRequest, Data: message.SessionRequestOptionData{}})
			if c.UseToken != 0 {
				opts = append(opts, message.Option{Kind: message.OptionKindTokenRequest, Data: message.TokenRequestOptionData{WindowSize: c.UseToken}})
			}
		}
	}
	return opts, cac
}

func (c *Client) checkAuthnReply(finalRep *message.AuthenticationReply) error {
	fail := finalRep.Type != message.AuthenticationReplySuccess

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
	if !c.UseSession {
		return nil
	}
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
	return nil
}

// authn running authentication in handshake
func (c *Client) authn(ctx context.Context, req message.Request, sconn net.Conn, initData []byte) error {
	if c.AuthenticationMethod == nil {
		c.AuthenticationMethod = auth.NoneClientAuthenticationMethod{}
	}
	// add authn options
	id := c.AuthenticationMethod.ID()
	if id == 6 {
		lg.Panic("SSL authentication is prohibited")
	}
	ops, cac := c.createAuthnOption(ctx, sconn, id, len(initData))
	req.Options.AddMany(ops)
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
		cac.FirstAuthReply <- aurep1
		// read error and reply
		err := <-cac.Error
		finalRep = <-cac.FinalAuthReply
		if err != nil {
			return err
		}
	}

	// check final reply
	return c.checkAuthnReply(finalRep)
}

// handshake handle the common handshake part of protocol
func (c *Client) handshake(
	ctx context.Context,
	op message.CommandCode,
	addr net.Addr,
	initData []byte,
	option *message.OptionSet,
) (net.Conn, *message.OperationReply, error) {
	netErr := net.OpError{
		Op:   "dial",
		Net:  "socks6",
		Addr: addr,
	}
	sconn, err := c.connectStream(ctx)
	if err != nil {
		netErr.Source = sconn.LocalAddr()
		return nil, nil, &netErr
	}
	netErr.Source = sconn.LocalAddr()

	cd := common.NewCancellableDefer(func() {
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

	if err = c.authn(ctx, req, sconn, initData); err != nil {
		netErr.Err = err
		return nil, nil, &netErr
	}

	opr, err := message.ParseOperationReplyFrom(sconn)
	if err != nil {
		return nil, nil, err
	}
	if opr.ReplyCode != 0 {
		netErr.Err = convertReplyError(opr.ReplyCode)
		return nil, nil, &netErr
	}
	if c.UseSession {
		if d, ok := opr.Options.GetData(message.OptionKindSessionID); ok {
			c.session = d.(message.SessionIDOptionData).ID
		} else {
			if len(c.session) == 0 {
				netErr.Err = errors.New("session fail")
				return nil, nil, &netErr
			}
		}
	}

	cd.Cancel()
	return sconn, opr, nil
}

func convertReplyError(code message.ReplyCode) error {
	switch code {
	case message.OperationReplyCommandNotSupported:
		return syscall.EOPNOTSUPP
	case message.OperationReplyAddressNotSupported:
		return syscall.EAFNOSUPPORT
	case message.OperationReplyNetworkUnreachable:
		return syscall.ENETUNREACH
	case message.OperationReplyHostUnreachable:
		return syscall.EHOSTUNREACH
	case message.OperationReplyNotAllowedByRule:
		return syscall.EACCES
	case message.OperationReplyConnectionRefused:
		return syscall.ECONNREFUSED
	case message.OperationReplyTimeout:
		return syscall.ETIMEDOUT

	case message.OperationReplySuccess:
		return nil
	case message.OperationReplyServerFailure:
		return ErrServerFailure
	case message.OperationReplyTTLExpired:
		return ErrTTLExpired
	}
	lg.Panic("not implemented reply code conversion")
	return nil
}
