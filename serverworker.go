package socks6

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/lg"
	"github.com/studentmain/socks6/internal/socket"
	"github.com/studentmain/socks6/message"
)

type CommandHandler func(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	clientInfo ClientInfo,
	initData []byte,
)

// ServerWorker is a customizeable SOCKS 6 server
type ServerWorker struct {
	Authenticator auth.ServerAuthenticator
	Rule          func(op message.CommandCode, dst, src net.Addr, cid string) bool

	CommandHandlers map[message.CommandCode]CommandHandler
	// VersionErrorHandler will handle non-SOCKS6 protocol request.
	// VersionErrorHandler should close connection by itself
	VersionErrorHandler func(ctx context.Context, ver message.ErrVersion, conn net.Conn)

	backlogListener sync.Map // map[string]*bl
}

type ClientInfo struct {
	Name      string
	SessionID []byte
}

// NewServerWorker create a standard SOCKS 6 server
func NewServerWorker() *ServerWorker {
	defaultAuth := &auth.DefaultServerAuthenticator{
		Methods: map[byte]auth.ServerAuthenticationMethod{},
	}
	defaultAuth.AddMethod(0, auth.NoneServerAuthenticationMethod{})
	// todo: remove them
	defaultAuth.AddMethod(2, auth.PasswordServerAuthenticationMethod{
		Passwords: map[string]string{
			"user": "pass",
		},
	})
	defaultAuth.AddMethod(0xdd, auth.FakeEchoServerAuthenticationMethod{})

	r := &ServerWorker{
		VersionErrorHandler: ReplyVersionSpecificError,
		Authenticator:       defaultAuth,
		backlogListener:     sync.Map{},
	}

	r.CommandHandlers = map[message.CommandCode]CommandHandler{
		message.CommandNoop:    r.NoopHandler,
		message.CommandConnect: r.ConnectHandler,
		message.CommandBind:    r.BindHandler,
	}

	return r
}

// ReplyVersionSpecificError guess which protocol client is using, reply corresponding "version error", then close conn
func ReplyVersionSpecificError(ctx context.Context, ver message.ErrVersion, conn net.Conn) {
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
		if errors.Is(err, message.ErrVersion{}) {
			closeConn.Cancel()
			s.VersionErrorHandler(ctx, err.(message.ErrVersion), conn)
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

		result2, err := s.Authenticator.ContinueAuthenticate(sac)
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

	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientName) {
			lg.Info(ccid, "not allowed by rule")
			conn.Write(message.NewOperationReplyWithCode(message.OperationReplyNotAllowedByRule).Marshal())
			return
		}
	}
	// per-command
	h, ok := s.CommandHandlers[req.CommandCode]
	if !ok {
		conn.Write(message.NewOperationReplyWithCode(message.OperationReplyCommandNotSupported).Marshal())
		return
	}
	lg.Trace(ccid, "start command specific process", req.CommandCode)
	info := ClientInfo{
		Name:      auth.ClientName,
		SessionID: auth.SessionID,
	}
	// it's handler's job to close conn
	closeConn.Cancel()
	h(ctx, conn, req, info, initData)
}

func (s *ServerWorker) ServeDatagram(
	ctx context.Context,
	addr net.Addr,
	data []byte,
	downlink func([]byte) error,
) {

}

func (s *ServerWorker) NoopHandler(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	info ClientInfo,
	initData []byte,
) {
	defer conn.Close()
	lg.Trace(conn3Tuple(conn), "noop")
	conn.Write(
		setSessionId(
			message.NewOperationReplyWithCode(message.OperationReplySuccess),
			info.SessionID,
		).Marshal())
}

func (s *ServerWorker) ConnectHandler(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	info ClientInfo,
	initData []byte,
) {
	defer conn.Close()
	clientAppliedOpt := message.StackOptionInfo{}
	remoteOpt := message.GetStackOptionInfo(req.Options, false)

	ccid := conn3Tuple(conn)
	lg.Trace(ccid, "dial to", req.Endpoint)

	// todo custom dialer
	rconn, remoteAppliedOpt, err := socket.DialWithOption(ctx, *req.Endpoint, remoteOpt)
	code := getReplyCode(err)
	reply := message.NewOperationReplyWithCode(code)
	setSessionId(reply, info.SessionID)

	if code != message.OperationReplySuccess {
		conn.Write(reply.Marshal())
		return
	}
	defer rconn.Close()

	lg.Trace(ccid, "remote conn established")
	appliedOpt := message.GetCombinedStackOptions(clientAppliedOpt, remoteAppliedOpt)
	reply.Options.AddMany(appliedOpt)

	if _, err := rconn.Write(initData); err != nil {
		// it will fail again at relay()
		lg.Info(ccid, "can't write initdata to remote connection")
	}
	reply.Endpoint = message.ParseAddr(rconn.LocalAddr().String())

	// it will fail again at relay() too
	if _, err := conn.Write(reply.Marshal()); err != nil {
		lg.Warning(ccid, "can't write reply")
	}

	relay(ctx, conn, rconn, 10*time.Minute)
	lg.Trace(ccid, "relay end")
}

func (s *ServerWorker) BindHandler(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	info ClientInfo,
	initData []byte,
) {
	closeConn := internal.NewCancellableDefer(func() {
		conn.Close()
	})

	defer closeConn.Defer()
	ccid := conn3Tuple(conn)
	// find backlogged listener
	ibl, accept := s.backlogListener.Load(req.Endpoint.String())
	if accept {
		bl := ibl.(*backlogListener)
		lg.Info(ccid, "trying accept backlogged connection at", bl.listener.Addr())
		// bl.handler is blocking, needn't cancel defer
		bl.handler(ctx, conn, req, info, initData)
		return
	}

	// not a backlogged accept

	remoteOpt := message.GetStackOptionInfo(req.Options, false)
	iBacklog, backlogged := remoteOpt[message.StackOptionTCPBacklog]

	listener, remoteAppliedOpt, err := socket.ListenerWithOption(ctx, *req.Endpoint, remoteOpt)
	lg.Info(ccid, "bind at", listener.Addr())
	code := getReplyCode(err)
	reply := message.NewOperationReplyWithCode(code)
	setSessionId(reply, info.SessionID)
	if code != message.OperationReplySuccess {
		conn.Write(reply.Marshal())
		return
	}

	// add backlog option to notify client
	if backlogged {
		lg.Info(ccid, "start backlogged bind at", listener.Addr())
		remoteAppliedOpt.Add(message.BaseStackOptionData{
			RemoteLeg: true,
			Level:     message.StackOptionLevelTCP,
			Code:      message.StackOptionCodeBacklog,
			Data: &message.BacklogOptionData{
				Backlog: iBacklog.(uint16),
			},
		})
	}

	reply.Endpoint = message.ParseAddr(listener.Addr().String())
	appliedOpt := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	reply.Options.AddMany(appliedOpt)

	if _, err := conn.Write(reply.Marshal()); err != nil {
		lg.Error(ccid, "can't write reply")
		return
	}
	// bind "handshake" done

	if backlogged {
		// let backloglistener handle conn
		closeConn.Cancel()
		backlog := iBacklog.(uint16)
		// backlog will only simulated on server
		// https://github.com/golang/go/issues/39000
		bl := newBacklogListener(listener, info.SessionID, conn, backlog)

		blAddr := listener.Addr().String()
		s.backlogListener.Store(blAddr, bl)
		lg.Trace(ccid, "start backlog listener worker")
		go bl.worker(ctx)
		return
	}
	// non backlogged path
	defer listener.Close()
	// timeout
	go func() {
		<-time.After(60 * time.Second)
		listener.Close()
	}()

	// accept a conn
	lg.Trace(ccid, "waiting inbound connection")
	rconn, err := listener.Accept()
	listener.Close()
	code2 := getReplyCode(err)
	reply2 := message.NewOperationReplyWithCode(code)
	setSessionId(reply2, info.SessionID)
	if code2 != message.OperationReplySuccess {
		conn.Write(reply2.Marshal())
		lg.Warning(ccid, "can't accept inbound connection", err)
		return
	}
	lg.Info(ccid, "inbound connection accepted")
	reply2.Endpoint = message.ParseAddr(rconn.RemoteAddr().String())
	conn.Write(reply2.Marshal())
	defer rconn.Close()

	relay(ctx, conn, rconn, 10*time.Minute)
	lg.Tracef(ccid, "relay end")
}

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
			if !bl.alive {
				s.backlogListener.Delete(key)
			}
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
		// if already recorded an err, that means another direction already closed
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
