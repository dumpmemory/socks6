package socks6

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/studentmain/socks6/auth"
	"github.com/studentmain/socks6/internal"
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

	CommandHandlers     map[message.CommandCode]CommandHandler
	VersionErrorHandler func(ctx context.Context, ver message.ErrVersion, conn net.Conn)
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
	}

	r.CommandHandlers = map[message.CommandCode]CommandHandler{
		message.CommandNoop:    r.NoopHandler,
		message.CommandConnect: r.ConnectHandler,
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
func (s *ServerWorker) ServeStream(
	ctx context.Context,
	conn net.Conn,
) {
	deferClose := true
	defer func() {
		if !deferClose {
			return
		}
		conn.Close()
	}()
	defer conn.Close()
	req, err := message.ParseRequestFrom(conn)
	if err != nil {
		// not socks6
		if errors.Is(err, message.ErrVersion{}) {
			deferClose = false
			s.VersionErrorHandler(ctx, err.(message.ErrVersion), conn)
			return
		}
		if errors.Is(err, message.ErrAddressTypeNotSupport) {
			conn.Write(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail).Marshal())
			conn.Write(message.NewOperationReplyWithCode(message.OperationReplyAddressNotSupported).Marshal())
			return
		} else {
			glog.Warning("can't parse request", err)
			return
		}
	}
	glog.V(2).Infof("request from %s, %+v", conn.RemoteAddr(), req)

	var initData []byte
	if am, ok := req.Options.GetData(message.OptionKindAuthenticationMethodAdvertisement); ok {
		initDataLen := int(am.(message.AuthenticationMethodAdvertisementOptionData).InitialDataLength)
		initData = make([]byte, initDataLen)
		if _, err = io.ReadFull(conn, initData); err != nil {
			glog.Error("can't read initdata", err)
			return
		}
	}

	result1, sac := s.Authenticator.Authenticate(ctx, conn, *req)
	var auth auth.ServerAuthenticationResult
	if result1.Success {
		auth = *result1
		reply := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplySuccess), *result1)
		glog.V(2).Infof("request %s authenticate %+v , %+v", conn.RemoteAddr(), auth, reply)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			glog.Error("can't write reply", err)
			return
		}
	} else if !result1.Continue {
		reply := message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			glog.Error("can't write reply", err)
			return
		}
	} else {
		reply1 := setAuthMethodInfo(message.NewAuthenticationReplyWithType(message.AuthenticationReplyFail), *result1)
		if _, err = conn.Write(reply1.Marshal()); err != nil {
			glog.Error("can't write reply1", err)
			return
		}
		result2, err := s.Authenticator.ContinueAuthenticate(sac)
		if err != nil {
			glog.Error("auth stage2 error", err)
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
		glog.V(2).Infof("request %s authenticate interactive %+v , %+v", conn.RemoteAddr(), auth, reply)
		if _, err = conn.Write(reply.Marshal()); err != nil {
			glog.Error("can't write reply2", err)
			return
		}
	}

	if !auth.Success {
		return
	}
	glog.V(2).Infof("request %s authenticate success", conn.RemoteAddr())

	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientName) {
			glog.V(2).Infof("request %s not allowed by rule", conn.RemoteAddr())
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
	glog.V(2).Infof("request %s start command specific process", conn.RemoteAddr())
	info := ClientInfo{
		Name:      auth.ClientName,
		SessionID: auth.SessionID,
	}
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
	//clientOpt := message.GetStackOptionInfo(req.Options, true)
	//clientAppliedOpt := socket.SetConnOpt(conn, clientOpt)
	//remoteOpt := message.GetStackOptionInfo(req.Options, false)

	glog.V(2).Infof("request %s dial to %s", conn.RemoteAddr(), req.Endpoint)

	// todo custom dialer
	//rconn, remoteAppliedOpt, err := socket.DialWithOption(ctx, *req.Endpoint, remoteOpt)
	d := net.Dialer{}
	rconn, err := d.DialContext(ctx, "tcp", req.Endpoint.String())
	code := getReplyCode(err)
	reply := message.NewOperationReplyWithCode(code)
	setSessionId(reply, info.SessionID)
	// mmp......
	// todo: either rewrite worker, or remove stack options, or write a blocking tcpconn
	//
	// https://stackoverflow.com/questions/28967701/golang-tcp-socket-cant-close-after-get-file?rq=1
	if code != message.OperationReplySuccess {
		conn.Write(reply.Marshal())
		glog.Info("unsuccess, exit")
		conn.(*net.TCPConn).CloseRead()
		conn.Close()
		return
	}
	defer rconn.Close()

	glog.V(2).Infof("request %s remote conn established", conn.RemoteAddr())
	//appliedOpt := message.GetCombinedStackOptions(clientAppliedOpt, remoteAppliedOpt)
	//reply.Options.AddMany(appliedOpt)

	if _, err := rconn.Write(initData); err != nil {
		// it will fail again at relay()
		glog.Error("can't write initdata to remote connection")
	}
	reply.Endpoint = message.NewAddrMust(rconn.LocalAddr().String())

	// it will fail again at relay() too
	if _, err := conn.Write(reply.Marshal()); err != nil {
		glog.Error("can't write reply")
	}

	relay(ctx, conn, rconn, 10*time.Minute)
	glog.V(2).Infof("request %s relay end", conn.RemoteAddr())
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
		glog.Warning(err)
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

func relay(ctx context.Context, c1, c2 net.Conn, timeout time.Duration) error {
	var wg sync.WaitGroup
	wg.Add(2)
	var err error = nil
	id := fmt.Sprintf("%s--%s <=> %s--%s", c1.LocalAddr(), c1.RemoteAddr(), c2.LocalAddr(), c2.RemoteAddr())
	glog.V(2).Infof("relay %s start", id)
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, c1, c2, timeout)
		if e != nil && err == nil {
			err = e
			c1.Close()
			c2.Close()
		}
	}()
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, c2, c1, timeout)
		if e != nil && err == nil {
			err = e
			c1.Close()
			c2.Close()
		}
	}()
	wg.Wait()

	glog.V(2).Infof("relay %s done %s", id, err)
	if err == io.EOF {
		return nil
	}
	return err
}

func relayOneDirection(ctx context.Context, c1, c2 net.Conn, timeout time.Duration) error {
	var done error = nil
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)

	id := fmt.Sprintf("%s--%s ==> %s--%s", c1.LocalAddr(), c1.RemoteAddr(), c2.LocalAddr(), c2.RemoteAddr())
	glog.V(2).Infof("relay %s start", id)
	go func() {
		<-ctx.Done()
		done = ctx.Err()
		glog.V(2).Infof("relay %s ctx done", id)
	}()
	defer glog.V(2).Infof("relay %s exit", id)
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
				glog.V(2).Infof("relay %s write error %s", id, eWrite)
				return eWrite
			}
			if nRead != nWrite {
				return io.ErrShortWrite
			}
		}
		if eRead != nil {
			glog.V(2).Infof("relay %s read error %s", id, eRead)
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
