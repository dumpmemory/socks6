package socks6

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/socket"
	"github.com/studentmain/socks6/message"
	"golang.org/x/net/icmp"
)

type CommandHandler func(
	ctx context.Context,
	cc ClientConn,
)

// todo socket like api?

// ServerWorker is a customizeable SOCKS 6 server
type ServerWorker struct {
	Authenticator auth.ServerAuthenticator
	Rule          func(cc ClientConn) bool

	CommandHandlers map[message.CommandCode]CommandHandler
	// VersionErrorHandler will handle non-SOCKS6 protocol request.
	// VersionErrorHandler should close connection by itself
	VersionErrorHandler func(ctx context.Context, ver message.ErrVersionMismatch, conn net.Conn)

	DatagramVersionErrorHandler func(ctx context.Context, ver message.ErrVersionMismatch, dgram Datagram)

	Outbound ServerOutbound

	// control UDP NAT filtering behavior,
	// mapping behavior is always Endpoint Independent.
	//
	// when false, use Endpoint Independent filtering (Full Cone)
	//
	// when true, use Address Dependent filtering (Restricted Cone)
	AddressDependentFiltering bool

	// require request message fully received in first packet
	//
	// Yes, TCP has no "packet" -- but that's only makes sense for people
	// who never need to touch the dark side of Internet.
	// Packet are everywhere in a packet switched network,
	// you can create a stream on it and hide it behind API,
	// but it's still a packet sequence on wire.
	IgnoreFragmentedRequest bool
	EnableICMP              bool

	backlogListener internal.SyncMap[string, *backlogListener] // map[string]*bl
	reservedUdpAddr internal.SyncMap[string, uint64]           // map[string]uint64
	udpAssociation  internal.SyncMap[uint64, *udpAssociation]  // map[uint64]*ua
}

// ServerOutbound is a group of function called by ServerWorker when a connection or listener is needed to fullfill client request
type ServerOutbound interface {
	Dial(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.Conn, message.StackOptionInfo, error)
	Listen(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.Listener, message.StackOptionInfo, error)
	ListenPacket(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.PacketConn, message.StackOptionInfo, error)
}

// InternetServerOutbound implements ServerOutbound, create a internet connection/listener
type InternetServerOutbound struct {
	DefaultIPv4        net.IP         // address used when udp association request didn't provide an address
	DefaultIPv6        net.IP         // address used when udp association request didn't provide an address
	MulticastInterface *net.Interface // address
}

func (i InternetServerOutbound) Dial(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.Conn, message.StackOptionInfo, error) {
	a := message.ConvertAddr(addr)
	return socket.DialWithOption(ctx, *a, option)
}
func (i InternetServerOutbound) Listen(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.Listener, message.StackOptionInfo, error) {
	a := message.ConvertAddr(addr)
	return socket.ListenerWithOption(ctx, *a, option)
}
func (i InternetServerOutbound) ListenPacket(ctx context.Context, option message.StackOptionInfo, addr *message.SocksAddr) (net.PacketConn, message.StackOptionInfo, error) {
	mcast := false
	if addr.AddressType != message.AddressTypeDomainName {
		ip := net.IP(addr.Address)
		if ip.IsMulticast() {
			mcast = true
		} else if ip.IsUnspecified() {
			if addr.AddressType == message.AddressTypeIPv4 {
				addr.Address = i.DefaultIPv4
			} else {
				addr.Address = i.DefaultIPv6
			}
		}
	} else {
		return nil, nil, message.ErrAddressTypeNotSupport
	}
	ua, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return nil, nil, err
	}
	if mcast {
		p, err2 := net.ListenMulticastUDP("udp", i.MulticastInterface, ua)
		return p, message.StackOptionInfo{}, err2
	}
	// todo what's going on? why 0.0.0.0 not work?
	p, err := net.ListenUDP("udp", ua)
	return p, message.StackOptionInfo{}, err
}

// NewServerWorker create a standard SOCKS 6 server
func NewServerWorker() *ServerWorker {
	defaultAuth := auth.NewServerAuthenticator()
	defaultAuth.AddMethod(auth.NoneServerAuthenticationMethod{})

	r := &ServerWorker{
		VersionErrorHandler: ReplyVersionSpecificError,
		Authenticator:       defaultAuth,
		Outbound: InternetServerOutbound{
			DefaultIPv4: common.GuessDefaultIPv4(),
			DefaultIPv6: common.GuessDefaultIPv6(),
		},
		backlogListener: internal.NewSyncMap[string, *backlogListener](),
		reservedUdpAddr: internal.NewSyncMap[string, uint64](),
		udpAssociation:  internal.NewSyncMap[uint64, *udpAssociation](),
	}

	r.CommandHandlers = map[message.CommandCode]CommandHandler{
		message.CommandNoop:         r.NoopHandler,
		message.CommandConnect:      r.ConnectHandler,
		message.CommandBind:         r.BindHandler,
		message.CommandUdpAssociate: r.UdpAssociateHandler,
	}

	return r
}

// ReplyVersionSpecificError guess which protocol client is using, reply corresponding "version error", then close conn
func ReplyVersionSpecificError(ctx context.Context, ver message.ErrVersionMismatch, conn net.Conn) {
	defer conn.Close()
	switch ver.Version {
	// socks4
	case 4:
		// header v0, reply 91
		conn.Write([]byte{0, 91})
	case 5:
		// no method allowed
		conn.Write([]byte{5, 0xff})
	case 6:
		// in case this function is used with a socks5 server
		conn.Write([]byte{6})
	case 'c', 'C', 'd', 'D', 'g', 'G', 'h', 'H', 'o', 'O', 'p', 'P', 't', 'T':
		conn.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\nThis is a SOCKS 6 proxy, not HTTP proxy\r\n"))
	default:
		conn.Write([]byte{6})
	}
}

// ServeStream process incoming TCP and TLS connection
// return when connection process complete, e.g. remote closed connection
func (s *ServerWorker) ServeStream(
	ctx context.Context,
	conn net.Conn,
) {
	closeConn := internal.NewCancellableDefer(func() {
		conn.Close()
	})
	defer closeConn.Defer()

	ccid := conn3Tuple(conn)

	// create a wrapper reader if necessary
	var conn1 io.Reader = conn
	if s.IgnoreFragmentedRequest {
		conn1 = &common.NetBufferOnlyReader{Conn: conn}
	}

	req, err := message.ParseRequestFrom(conn1)
	if err != nil {
		closeConn.Cancel()
		s.handleRequestError(ctx, conn, err)
		return
	}
	lg.Tracef("request from %s, %+v", ccid, req)

	var initData []byte
	if am, ok := req.Options.GetData(message.OptionKindAuthenticationMethodAdvertisement); ok {
		initDataLen := int(am.(message.AuthenticationMethodAdvertisementOptionData).InitialDataLength)
		initData = make([]byte, initDataLen)
		if _, err = io.ReadFull(conn, initData); err != nil {
			lg.Warningf("%s can't read %d bytes initdata: %s", ccid, initDataLen, err)
			return
		}
	}

	auth := s.authn(ctx, conn, req)
	if auth == nil {
		return
	}
	if !auth.Success {
		lg.Info(ccid, "authenticate fail")
		return
	}
	lg.Trace(ccid, "authenticate success")
	cc := ClientConn{
		Conn:    conn,
		Request: req,

		ClientId: auth.ClientName,
		Session:  auth.SessionID,

		InitialData: initData,
	}

	if s.Rule != nil && !s.Rule(cc) {
		lg.Info(ccid, "not allowed by rule")
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplyNotAllowedByRule).Marshal())
		return
	}

	// per-command
	h, ok := s.CommandHandlers[req.CommandCode]
	if !ok {
		lg.Warning(ccid, "command not supported", req.CommandCode)
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplyCommandNotSupported).Marshal())
		return
	}
	lg.Trace(ccid, "start command specific process", req.CommandCode)

	defer s.Authenticator.SessionConnClose(auth.SessionID)
	// it's handler's job to close conn
	closeConn.Cancel()
	h(ctx, cc)
}

func (s *ServerWorker) handleRequestError(
	ctx context.Context,
	conn net.Conn,
	err error,
) {
	evm := message.ErrVersionMismatch{}
	if errors.As(err, &evm) {
		s.VersionErrorHandler(ctx, evm, conn)
		return
	}
	defer conn.Close()
	// detect and reply addr not support early, as auth can't continue
	if errors.Is(err, message.ErrAddressTypeNotSupport) {
		conn.Write(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail).Marshal())
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplyAddressNotSupported).Marshal())
		return
	} else {
		lg.Warningf("can't parse request from %s, %+v", conn3Tuple(conn), err)
		return
	}
}

func (s *ServerWorker) authn(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
) *auth.ServerAuthenticationResult {
	ccid := conn3Tuple(conn)
	result1, sac := s.Authenticator.Authenticate(ctx, conn, *req)

	auth := *result1
	if result1.Success {
		// one stage auth, success
		auth = *result1
		reply := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplySuccess), *result1)
		lg.Debugf("%s authenticate %+v , %+v", ccid, auth, reply)
		if _, err := conn.Write(reply.Marshal()); err != nil {
			lg.Warning(ccid, "can't write auth reply", err)
			return nil
		}
	} else if !result1.Continue {
		// one stage auth, can't continue
		reply := message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail)
		if _, err := conn.Write(reply.Marshal()); err != nil {
			lg.Warning(ccid, "can't write reply", err)
			return nil
		}
	} else {
		// two stage auth
		reply1 := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail), *result1)
		if _, err := conn.Write(reply1.Marshal()); err != nil {
			lg.Warning(ccid, "can't write auth reply 1", err)
			return nil
		}
		// run stage 2
		lg.Debug(ccid, "auth stage 2")

		result2, err := s.Authenticator.ContinueAuthenticate(sac, *req)
		if err != nil {
			lg.Warning(ccid, "auth stage 2 error", err)
			conn.Write(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail).Marshal())
			return nil
		}
		auth = *result2
		reply := setAuthMethodInfo(message.NewAuthenticationReply(), *result2)
		if result2.Success {
			reply.Type = message.AuthenticationReplySuccess
		} else {
			reply.Type = message.AuthenticationReplyFail
		}
		lg.Debugf("%s auth stage 2 done %+v , %+v", ccid, auth, reply)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			lg.Warning(ccid, "can't write auth reply 2", err)
			return nil
		}
	}
	return &auth
}

func (s *ServerWorker) ServeDatagramSource(
	ctx context.Context,
	dgramSrc DatagramSource,
) {
	assoc, h := s.handleFirstDatagram(ctx, *dgramSrc.ReadDatagram())
	assoc.handleUdpUp(ctx, ClientPacket{
		Message:  h,
		Source:   dgramSrc.Addr,
		Downlink: dgramSrc.Downlink,
	})

	for {
		d := dgramSrc.ReadDatagram()
		if d == nil {
			return
		}
		h, err := message.ParseUDPMessageFrom(bytes.NewReader(d.Data))
		if err != nil {
			lg.Warning(err)
			return
		}
		assoc.handleUdpUp(ctx, ClientPacket{
			Message:  h,
			Source:   dgramSrc.Addr,
			Downlink: dgramSrc.Downlink,
		})
	}
}

func (s *ServerWorker) ServeDatagram(
	ctx context.Context,
	dgram Datagram,
) {
	assoc, h := s.handleFirstDatagram(ctx, dgram)
	assoc.handleUdpUp(ctx, ClientPacket{
		Message:  h,
		Source:   dgram.Addr,
		Downlink: dgram.Downlink,
	})
}

func (s *ServerWorker) handleFirstDatagram(
	ctx context.Context,
	dgram Datagram,
) (*udpAssociation, *message.UDPMessage) {
	h, err := message.ParseUDPMessageFrom(bytes.NewReader(dgram.Data))
	if err != nil {
		evm := message.ErrVersionMismatch{}
		if errors.As(err, &evm) && s.DatagramVersionErrorHandler != nil {
			s.DatagramVersionErrorHandler(ctx, evm, dgram)
		}
		return nil, nil
	}
	assoc, ok := s.udpAssociation.Load(h.AssociationID)
	if !ok {
		return nil, nil
	}
	return assoc, h
}

func (s *ServerWorker) NoopHandler(
	ctx context.Context,
	cc ClientConn,
) {
	defer cc.Conn.Close()
	lg.Trace(cc.ConnId(), "noop")
	cc.WriteReplyCode(message.OperationReplySuccess)
}

func (s *ServerWorker) ConnectHandler(
	ctx context.Context,
	cc ClientConn,
) {
	defer cc.Conn.Close()
	clientAppliedOpt := message.StackOptionInfo{}
	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)

	lg.Trace(cc.ConnId(), "dial to", cc.Destination())

	rconn, remoteAppliedOpt, err := s.Outbound.Dial(ctx, remoteOpt, cc.Destination())
	code := getReplyCode(err)

	if code != message.OperationReplySuccess {
		cc.WriteReplyCode(code)
		return
	}
	defer rconn.Close()

	lg.Trace(cc.ConnId(), "remote conn established")
	if _, err := rconn.Write(cc.InitialData); err != nil {
		// it will fail again at relay()
		lg.Info(cc.ConnId(), "can't write initdata to remote connection")
	}

	appliedOpt := message.GetCombinedStackOptions(clientAppliedOpt, remoteAppliedOpt)
	options := message.NewOptionSet()
	options.AddMany(appliedOpt)
	// it will fail again at relay() too
	if err := cc.WriteReply(code, rconn.LocalAddr(), options); err != nil {
		lg.Warning(cc.ConnId(), "can't write reply", err)
	}

	relay(ctx, cc.Conn, rconn, 10*time.Minute)
	lg.Trace(cc.ConnId(), "relay end")
}

func (s *ServerWorker) BindHandler(
	ctx context.Context,
	cc ClientConn,
) {
	closeConn := internal.NewCancellableDefer(func() {
		cc.Conn.Close()
	})

	defer closeConn.Defer()
	// find backlogged listener
	bl, accept := s.backlogListener.Load(cc.Destination().String())
	if accept {
		lg.Info(cc.ConnId(), "trying accept backlogged connection at", bl.listener.Addr())
		// bl.handler is blocking, needn't cancel defer
		bl.handler(ctx, cc)
		return
	}

	// not a backlogged accept

	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)
	iBacklog, backlogged := remoteOpt[message.StackOptionTCPBacklog]

	listener, remoteAppliedOpt, err := s.Outbound.Listen(ctx, remoteOpt, cc.Destination())
	lg.Info(cc.ConnId(), "bind at", listener.Addr())
	code := getReplyCode(err)
	if code != message.OperationReplySuccess {
		cc.WriteReplyCode(code)
		return
	}

	// add backlog option to notify client
	if backlogged {
		lg.Info(cc.ConnId(), "start backlogged bind at", listener.Addr())
		remoteAppliedOpt.Add(message.BaseStackOptionData{
			RemoteLeg: true,
			Level:     message.StackOptionLevelTCP,
			Code:      message.StackOptionCodeBacklog,
			Data: &message.BacklogOptionData{
				Backlog: iBacklog.(uint16),
			},
		})
	}

	appliedOpt := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	options := message.NewOptionSet()
	options.AddMany(appliedOpt)

	if err = cc.WriteReply(code, listener.Addr(), options); err != nil {
		lg.Error(cc.ConnId(), "can't write reply", err)
		return
	}
	// bind "handshake" done

	if backlogged {
		// let backloglistener handle conn
		closeConn.Cancel()
		backlog := iBacklog.(uint16)
		// backlog will only simulated on server
		// https://github.com/golang/go/issues/39000
		bl := newBacklogListener(listener, cc, backlog)

		blAddr := listener.Addr().String()
		s.backlogListener.Store(blAddr, bl)
		lg.Trace(cc.ConnId(), "start backlog listener worker")
		go bl.worker(ctx)
		return
	}
	// non backlogged path
	defer listener.Close()
	// timeout or cancelled
	go func() {
		select {
		case <-time.After(60 * time.Second):
		case <-ctx.Done():
		}
		// can always close listener after 60s
		// in normal condition, listener accept exactly 1 conn, then close, another close call is unnecessary but safe
		// in error condition, of course close listener
		listener.Close()
	}()

	// accept a conn
	lg.Trace(cc.ConnId(), "waiting inbound connection")
	rconn, err := listener.Accept()
	listener.Close()
	code2 := getReplyCode(err)
	if code2 != message.OperationReplySuccess {
		cc.WriteReplyCode(code2)
		lg.Warning(cc.ConnId(), "can't accept inbound connection", err)
		return
	}
	lg.Info(cc.ConnId(), "inbound connection accepted")
	cc.WriteReplyAddr(code2, rconn.RemoteAddr())
	defer rconn.Close()

	relay(ctx, cc.Conn, rconn, 10*time.Minute)
	lg.Trace(cc.ConnId(), "relay end")
}

func (s *ServerWorker) UdpAssociateHandler(
	ctx context.Context,
	cc ClientConn,
) {
	closeConn := internal.NewCancellableDefer(func() {
		cc.Conn.Close()
	})

	defer closeConn.Defer()

	destStr := cc.Destination().String()
	rid, reserved := s.reservedUdpAddr.Load(destStr)
	// already reserved
	if reserved {
		rua, ok := s.udpAssociation.Load(rid)
		if !ok {
			lg.Warning("reserve port exist after association delete")
		} else {
			// not same session, fail
			if !bytes.Equal(rua.cc.Session, cc.Session) {
				cc.WriteReplyCode(message.OperationReplyConnectionRefused)
				return
			}
		}
	}

	// reserve check pass
	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)
	pc, remoteAppliedOpt, err := s.Outbound.ListenPacket(ctx, remoteOpt, cc.Destination())
	code := getReplyCode(err)
	if code != message.OperationReplySuccess {
		cc.WriteReplyCode(code)
		return
	}
	var reservedAddr net.Addr
	// reserve port
	if ippod, ok := remoteOpt[message.StackOptionUDPPortParity]; ok {
		appliedPpod := message.PortParityOptionData{
			Reserve: true,
			Parity:  message.StackPortParityOptionParityNo,
		}
		// calculate port to reserve
		ppod := ippod.(message.PortParityOptionData)
		if ppod.Reserve {
			s6a := message.ConvertAddr(pc.LocalAddr())
			if s6a.Port&1 == 0 {
				s6a.Port += 1
				appliedPpod.Parity = message.StackPortParityOptionParityEven
			} else {
				s6a.Port -= 1
				appliedPpod.Parity = message.StackPortParityOptionParityOdd
			}
			reservedAddr = s6a
		}
		// check and create reply option
		if !common.UdpPortAvaliable(reservedAddr) {
			reservedAddr = nil
			appliedPpod.Reserve = false
		} else {
			remoteAppliedOpt.Add(message.BaseStackOptionData{
				RemoteLeg: true,
				Level:     message.StackOptionLevelUDP,
				Code:      message.StackOptionCodePortParity,
				Data:      &appliedPpod,
			})
		}
	}
	// check icmp option
	icmpOn := false
	if s.EnableICMP {
		if iicmp, ok := remoteOpt[message.StackOptionUDPUDPError]; ok {
			i := iicmp.(message.UDPErrorOptionData)
			if i.Availability {
				icmpOn = true
				remoteAppliedOpt.Add(message.BaseStackOptionData{
					RemoteLeg: true,
					Level:     message.StackOptionLevelUDP,
					Code:      message.StackOptionCodeUDPError,
					Data: &message.UDPErrorOptionData{
						Availability: true,
					},
				})
			}
		}
	}

	so := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	opset := message.NewOptionSet()
	opset.AddMany(so)
	cc.WriteReply(message.OperationReplySuccess, pc.LocalAddr(), opset)
	// start association
	assoc := newUdpAssociation(cc, pc, reservedAddr, s.AddressDependentFiltering, icmpOn)
	s.udpAssociation.Store(assoc.id, assoc)
	lg.Trace("start udp assoc", assoc.id)
	if reservedAddr != nil {
		s.reservedUdpAddr.Store(reservedAddr.String(), assoc.id)
	}
	closeConn.Cancel()

	go assoc.handleTcpUp(ctx)
	go assoc.handleUdpDown(ctx)
}

func (s *ServerWorker) ForwardICMP(ctx context.Context, msg *icmp.Message, ip *net.IPAddr, ver int) {
	code, reporter, hdr := convertICMPError(msg, ip, ver)
	if hdr == nil {
		return
	}
	ipSrc, ipDst, proto, err := parseSrcDstAddrFromIPHeader(hdr, ver)
	if err != nil {
		lg.Info("ICMP IP header parse fail", err)
		return
	}
	if proto != 17 {
		return
	}
	// todo faster way to find corresponding assoc
	s.udpAssociation.Range(func(key uint64, value *udpAssociation) bool {
		ua := value
		// icmp disabled
		if !ua.icmpOn {
			return true
		}
		// not same origin
		if ua.udp.LocalAddr().String() != ipSrc.String() {
			return true
		}
		ua.handleIcmpDown(ctx, code, ipSrc, ipDst, reporter)
		return true
	})
}

// todo request clear resource by resource themselves

// ClearUnusedResource clear no longer used resources (UDP associations, etc.)
// only need to call it once for each ServerWorker
func (s *ServerWorker) ClearUnusedResource(ctx context.Context) {
	stop := false

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx2.Done()
		stop = true
	}()
	tick := time.NewTicker(1 * time.Minute)

	for !stop {
		<-tick.C

		s.backlogListener.Range(func(key string, value *backlogListener) bool {
			bl := value
			if bl.alive {
				return true
			}
			s.backlogListener.Delete(key)
			return true
		})
		s.udpAssociation.Range(func(key uint64, value *udpAssociation) bool {
			ua := value
			if ua.alive {
				return true
			}
			s.udpAssociation.Delete(key)
			s.reservedUdpAddr.Delete(ua.pair)
			return true
		})
	}
}

// setSessionId append session id option to operation reply when id is not null
func setSessionId(oprep *message.OperationReply, id []byte) *message.OperationReply {
	if id == nil {
		return oprep
	}
	oprep.Options.Add(message.Option{
		Kind: message.OptionKindSessionID,
		Data: message.SessionIDOptionData{
			ID: id,
		},
	})
	return oprep
}

func setAuthMethodInfo(arep *message.AuthenticationReply, result auth.ServerAuthenticationResult) *message.AuthenticationReply {
	if result.SelectedMethod != 0 && result.SelectedMethod != 0xff {
		arep.Options.Add(message.Option{
			Kind: message.OptionKindAuthenticationMethodSelection,
			Data: message.AuthenticationMethodSelectionOptionData{
				Method: result.SelectedMethod,
			},
		})
	}
	if result.MethodData != nil {
		arep.Options.Add(message.Option{
			Kind: message.OptionKindAuthenticationData,
			Data: message.AuthenticationDataOptionData{
				Method: result.SelectedMethod,
				Data:   result.MethodData,
			},
		})
	}
	return arep
}
