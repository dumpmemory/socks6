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
	"github.com/studentmain/socks6/internal/socket"
	"github.com/studentmain/socks6/message"
)

type CommandHandler func(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	auth AuthenticationResult,
	initData []byte,
)

type ServerWorker struct {
	VersionErrorHandler func(ctx context.Context, ver message.ErrVersion, conn net.Conn)

	Authenticator Authenticator

	Rule func(op message.CommandCode, dst, src net.Addr, cid ClientID) bool

	CommandHandlers map[message.CommandCode]CommandHandler
}

func NewServerWorker() *ServerWorker {
	r := &ServerWorker{
		VersionErrorHandler: ReplyErrorByVersion,
		Authenticator:       NullAuthenticator{},
	}
	r.CommandHandlers = map[message.CommandCode]CommandHandler{
		message.CommandNoop:    r.NoopHandler,
		message.CommandConnect: r.ConnectHandler,
	}
	return r
}

// ReplyErrorByVersion guess which protocol client is using, reply corresponding "version error", then close conn
func ReplyErrorByVersion(ctx context.Context, ver message.ErrVersion, conn net.Conn) {
	defer conn.Close()
	switch ver.Version {
	// socks4
	case 4:
		// header v0, reply 91
		conn.Write([]byte{0, 91})
	case 5:
		conn.Write([]byte{5})
	case 'c', 'C', 'd', 'D', 'g', 'G', 'h', 'H', 'o', 'O', 'p', 'P', 't', 'T':
		conn.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\nThis is a SOCKS 6 proxy, not HTTP proxy"))
	default:
		conn.Write([]byte{6})
	}
}

func (s *ServerWorker) ServeStream(
	ctx context.Context,
	conn net.Conn,
) {
	deferClose := true
	defer func() {
		if deferClose {
			conn.Close()
		}
	}()

	req, err := message.ParseRequestFrom(conn)
	if err != nil {
		// not socks6
		if errors.Is(err, message.ErrVersion{}) {
			deferClose = false
			s.VersionErrorHandler(ctx, err.(message.ErrVersion), conn)
			return
		}
		if errors.Is(err, message.ErrAddressTypeNotSupport) {
			conn.Write((&message.AuthenticationReply{
				Type: message.AuthenticationReplyFail,
			}).Marshal())
			conn.Write((&message.OperationReply{
				ReplyCode: message.OperationReplyAddressNotSupported,
				Endpoint:  message.NewAddrMust(":0"),
			}).Marshal())
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

	auth, reply := s.Authenticator.Authenticate(*req)

	glog.V(2).Infof("request %s authenticate %+v , %+v", conn.RemoteAddr(), auth, reply)

	if _, err = conn.Write(reply.Marshal()); err != nil {
		glog.Error("can't write reply", err)
		return
	}

	if !auth.Success {
		glog.Warningf("interactive auth not implemented")
		// todo: slow path, but how?
		return
	}
	glog.V(2).Infof("request %s authenticate success", conn.RemoteAddr())

	if s.Rule != nil {

		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientID) {
			glog.V(2).Infof("request %s not allowed by rule", conn.RemoteAddr())
			conn.Write((&message.OperationReply{
				ReplyCode: message.OperationReplyAddressNotSupported,
			}).Marshal())
			return
		}
	}
	// per-command
	h, ok := s.CommandHandlers[req.CommandCode]
	if !ok {
		conn.Write((&message.OperationReply{
			ReplyCode: message.OperationReplyCommandNotSupported,
			Endpoint:  message.NewAddrMust(":0"),
		}).Marshal())
		return
	}
	glog.V(2).Infof("request %s start command specific process", conn.RemoteAddr())

	h(ctx, conn, req, auth, initData)
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
	auth AuthenticationResult,
	initData []byte,
) {
	conn.Write(
		setSessionId(
			&message.OperationReply{
				ReplyCode: message.OperationReplySuccess,
			},
			auth.SessionID,
		).Marshal())
}

func (s *ServerWorker) ConnectHandler(
	ctx context.Context,
	conn net.Conn,
	req *message.Request,
	auth AuthenticationResult,
	initData []byte,
) {
	clientOpt := message.GetStackOptionInfo(req.Options, true)
	clientAppliedOpt := socket.SetConnOpt(conn, clientOpt)
	remoteOpt := message.GetStackOptionInfo(req.Options, false)

	glog.V(2).Infof("request %s dial to %s", conn.RemoteAddr(), req.Endpoint)
	rconn, remoteAppliedOpt, err := socket.DialWithOption(ctx, *req.Endpoint, remoteOpt)
	code := getReplyCode(err)
	reply := message.OperationReply{
		ReplyCode: code,
		Options:   message.NewOptionSet(),
	}
	setSessionId(&reply, auth.SessionID)
	if code != message.OperationReplySuccess {
		conn.Write(reply.Marshal())
		return
	}
	defer rconn.Close()

	glog.V(2).Infof("request %s remote conn established", conn.RemoteAddr())
	appliedOpt := message.GetCombinedStackOptions(clientAppliedOpt, remoteAppliedOpt)
	reply.Options.AddMany(appliedOpt)

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
	buf := make([]byte, 2048) // classic buffer size from "that" proxy
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
