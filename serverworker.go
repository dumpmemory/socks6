package socks6

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/socket"
	"github.com/studentmain/socks6/message"
)

type CommandHandler func(
	ctx context.Context,
	cc ClientConn,
)

// ServerWorker is a customizeable SOCKS 6 server
type ServerWorker struct {
	Authenticator auth.ServerAuthenticator
	Rule          func(cc ClientConn) bool

	CommandHandlers map[message.CommandCode]CommandHandler
	// VersionErrorHandler will handle non-SOCKS6 protocol request.
	// VersionErrorHandler should close connection by itself
	VersionErrorHandler func(ctx context.Context, ver message.ErrVersionMismatch, conn net.Conn)

	Outbound ServerOutbound

	backlogListener *sync.Map // map[string]*bl
	reservedUdpAddr *sync.Map // map[string]uint64
	udpAssociation  *sync.Map // map[uint64]*ua
}

type ServerOutbound interface {
	Dial(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.Conn, message.StackOptionInfo, error)
	Listen(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.Listener, message.StackOptionInfo, error)
	ListenPacket(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.PacketConn, message.StackOptionInfo, error)
}

type InternetServerOutbound struct {
	DefaultIPv4        net.IP
	DefaultIPv6        net.IP
	MulticastInterface *net.Interface
}

func (i InternetServerOutbound) Dial(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.Conn, message.StackOptionInfo, error) {
	a := message.ConvertAddr(addr)
	return socket.DialWithOption(ctx, *a, option)
}
func (i InternetServerOutbound) Listen(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.Listener, message.StackOptionInfo, error) {
	a := message.ConvertAddr(addr)
	return socket.ListenerWithOption(ctx, *a, option)
}
func (i InternetServerOutbound) ListenPacket(ctx context.Context, option message.StackOptionInfo, addr *message.Socks6Addr) (net.PacketConn, message.StackOptionInfo, error) {
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
		p, err := net.ListenMulticastUDP("udp", i.MulticastInterface, ua)
		return p, message.StackOptionInfo{}, err
	}

	p, err := net.ListenUDP("udp", ua)
	return p, message.StackOptionInfo{}, err
}

// NewServerWorker create a standard SOCKS 6 server
func NewServerWorker() *ServerWorker {
	defaultAuth := &auth.DefaultServerAuthenticator{
		Methods: map[byte]auth.ServerAuthenticationMethod{},
	}
	defaultAuth.AddMethod(auth.NoneServerAuthenticationMethod{})

	r := &ServerWorker{
		VersionErrorHandler: ReplyVersionSpecificError,
		Authenticator:       defaultAuth,
		Outbound: InternetServerOutbound{
			DefaultIPv4: guessDefaultIP4(),
			DefaultIPv6: guessDefaultIP6(),
		},
		backlogListener: &sync.Map{},
		reservedUdpAddr: &sync.Map{},
		udpAssociation:  &sync.Map{},
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

	req, err := message.ParseRequestFrom(conn)
	if err != nil {
		// not socks6
		evm := message.ErrVersionMismatch{}
		if errors.As(err, &evm) {
			closeConn.Cancel()
			s.VersionErrorHandler(ctx, evm, conn)
			return
		}
		// detect and reply addr not support early, as auth can't continue
		if errors.Is(err, message.ErrAddressTypeNotSupport) {
			conn.Write(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail).Marshal())
			conn.Write(message.NewOperationReplyWithCode(message.OperationReplyAddressNotSupported).Marshal())
			return
		} else {
			lg.Warningf("can't parse request from %s, %+v", ccid, err)
			return
		}
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

	result1, sac := s.Authenticator.Authenticate(ctx, conn, *req)
	// final auth result
	auth := *result1
	if result1.Success {
		// one stage auth, success
		auth = *result1
		reply := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplySuccess), *result1)
		lg.Debugf("%s authenticate %+v , %+v", ccid, auth, reply)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			lg.Warning(ccid, "can't write auth reply", err)
			return
		}
	} else if !result1.Continue {
		reply := message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			lg.Warning(ccid, "can't write reply", err)
			return
		}
	} else {
		// two stage auth
		reply1 := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail), *result1)
		if _, err = conn.Write(reply1.Marshal()); err != nil {
			lg.Warning(ccid, "can't write auth reply 1", err)
			return
		}
		// run stage 2
		lg.Debug(ccid, "auth stage 2")

		result2, err := s.Authenticator.ContinueAuthenticate(sac, *req)
		if err != nil {
			lg.Warning(ccid, "auth stage 2 error", err)
			conn.Write(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail).Marshal())
			return
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
			return
		}
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

	if s.Rule != nil {
		if !s.Rule(cc) {
			lg.Info(ccid, "not allowed by rule")
			conn.Write(message.NewOperationReplyWithCode(message.OperationReplyNotAllowedByRule).Marshal())
			return
		}
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

func (s *ServerWorker) ServeDatagram(
	ctx context.Context,
	addr net.Addr,
	data []byte,
	downlink func([]byte) error,
) {
	h, err := message.ParseUDPHeaderFrom(bytes.NewReader(data))
	if err != nil {
		return
	}
	iassoc, ok := s.udpAssociation.Load(h.AssociationID)
	if !ok {
		return
	}
	assoc := iassoc.(*udpAssociation)

	cp := ClientPacket{
		Message:  h,
		Source:   addr,
		Downlink: downlink,
	}
	assoc.handleUdpUp(ctx, cp)
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

	// todo custom dialer
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
	ibl, accept := s.backlogListener.Load(cc.Destination().String())
	if accept {
		bl := ibl.(*backlogListener)
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

	if err := cc.WriteReply(code, listener.Addr(), options); err != nil {
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

	destStr := message.AddrString(cc.Destination())
	irid64, reserved := s.reservedUdpAddr.Load(destStr)
	// already reserved
	if reserved {
		rid := irid64.(uint64)
		irua, ok := s.udpAssociation.Load(rid)
		if !ok {
			lg.Warning("reserve port exist after association delete")
		} else {
			rua := irua.(*udpAssociation)
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
		if !udpPortAvaliable(reservedAddr) {
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
	so := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	opset := message.NewOptionSet()
	opset.AddMany(so)
	cc.WriteReply(message.OperationReplySuccess, pc.LocalAddr(), opset)
	// start association
	assoc := newUdpAssociation(cc, pc, reservedAddr)
	s.udpAssociation.Store(assoc.id, assoc)
	lg.Trace("start udp assoc", assoc.id)
	if reservedAddr != nil {
		s.reservedUdpAddr.Store(message.AddrString(reservedAddr), assoc.id)
	}
	closeConn.Cancel()

	go assoc.handleTcpUp(ctx)
	go assoc.handleUdpDown(ctx)
}

// ClearUnusedResource clear no longer used resources (UDP associations, etc.)
// only need to call it once for each ServerWorker
func (s *ServerWorker) ClearUnusedResource(ctx context.Context) {
	stop := false

	go func() {
		<-ctx.Done()
		stop = true
	}()
	tick := time.NewTicker(1 * time.Minute)

	for !stop {
		<-tick.C

		s.backlogListener.Range(func(key, value interface{}) bool {
			bl := value.(*backlogListener)
			if bl.alive {
				return true
			}
			s.backlogListener.Delete(key)
			return true
		})
		s.udpAssociation.Range(func(key, value interface{}) bool {
			ua := value.(*udpAssociation)
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

// getReplyCode convert dial error to socks6 error code
func getReplyCode(err error) message.ReplyCode {
	if err == nil {
		return message.OperationReplySuccess
	}
	netErr, ok := err.(net.Error)
	if !ok {
		lg.Warning(err)
		return message.OperationReplyServerFailure
	}
	if netErr.Timeout() {
		return message.OperationReplyTimeout
	}
	opErr, ok := netErr.(*net.OpError)
	if !ok {
		return message.OperationReplyServerFailure
	}

	switch t := opErr.Err.(type) {
	case *os.SyscallError:
		errno, ok := t.Err.(syscall.Errno)
		if !ok {
			return message.OperationReplyServerFailure
		}
		// windows use windows.WSAExxxx error code, so this is necessary
		switch socket.ConvertErrno(errno) {
		case syscall.ENETUNREACH:
			return message.OperationReplyNetworkUnreachable
		case syscall.EHOSTUNREACH:
			return message.OperationReplyHostUnreachable
		case syscall.ECONNREFUSED:
			return message.OperationReplyConnectionRefused
		case syscall.ETIMEDOUT:
			return message.OperationReplyTimeout
		default:
			return message.OperationReplyServerFailure
		}
	}
	return message.OperationReplyServerFailure
}

func relay(ctx context.Context, c, r net.Conn, timeout time.Duration) error {
	var wg sync.WaitGroup
	wg.Add(2)
	var err error = nil
	lg.Debugf("relay %s start", relayConnTuple(c, r))
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, c, r, timeout)
		// if already recorded an err, then another direction is already closed
		if e != nil && err == nil {
			err = e
			c.Close()
			r.Close()
		}
	}()
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, r, c, timeout)
		if e != nil && err == nil {
			err = e
			c.Close()
			r.Close()
		}
	}()
	wg.Wait()

	lg.Debugf("relay %s done %s", relayConnTuple(c, r), err)
	if err == io.EOF {
		return nil
	}
	return err
}

func relayOneDirection(ctx context.Context, c1, c2 net.Conn, timeout time.Duration) error {
	var done error = nil
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	id := relayConnTuple(c1, c2)
	lg.Debugf("relayOneDirection %s start", id)
	go func() {
		<-ctx.Done()
		done = ctx.Err()
	}()
	defer lg.Debugf("relayOneDirection %s exit", id)
	// copy pasted from io.Copy with some modify
	for {
		c1.SetReadDeadline(time.Now().Add(timeout))
		nRead, eRead := c1.Read(buf)
		if done != nil {
			return done
		}

		if nRead > 0 {
			c2.SetWriteDeadline(time.Now().Add(timeout))
			nWrite, eWrite := c2.Write(buf[:nRead])
			if done != nil {
				return done
			}

			if eWrite != nil {
				lg.Debugf("relayOneDirection %s write error %s", id, eWrite)
				return eWrite
			}
			if nRead != nWrite {
				return io.ErrShortWrite
			}
		}
		if eRead != nil {
			lg.Debugf("relayOneDirection %s read error %s", id, eRead)
			return eRead
		}
	}
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
