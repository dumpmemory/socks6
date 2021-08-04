package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/windows"
)

type Server struct {
	Address       string
	CleartextPort uint16
	EncryptedPort uint16

	Cert tls.Certificate

	VersionErrorHandler func(head []byte, conn net.Conn)

	tcpListener  *net.TCPListener
	tlsListener  net.Listener
	udpListener  *net.UDPConn
	dtlsListener net.Listener

	cancellationToken context.Context

	udpAssociations       map[uint64]*udpAssociationInfo
	authenticator         DefaultAuthenticator
	backloggedConnections map[string]backloggedConnectionInfo
	reservedPorts         map[string]udpReservedPort

	Rule func(op byte, dst, src net.Addr, cid ClientID) bool
}

type backloggedConnectionInfo struct {
	sessionId  []byte
	clientConn chan net.Conn
	done       chan int
	remoteAddr string
}

type udpAssociationInfo struct {
	tcp bool
	// udp or dtls 5 tuple
	dgramLocal  net.Addr
	dgramRemote net.Addr
	dgramNet    string

	received sync.Mutex
	downlink func(b []byte) (int, error)
	conn     net.UDPConn

	icmpError bool
	// todo: how? allocate port when req?
	reservedPort uint16
}

type udpReservedPort struct {
	sessionId []byte
	conn      *net.UDPConn
}

func (s *Server) Start() {
	s.udpAssociations = map[uint64]*udpAssociationInfo{}
	s.backloggedConnections = map[string]backloggedConnectionInfo{}
	s.authenticator = NewDefaultAuthenticator()

	cptxt := strconv.FormatUint(uint64(s.CleartextPort), 10)
	cptxt = net.JoinHostPort(s.Address, cptxt)
	eptxt := strconv.FormatUint(uint64(s.EncryptedPort), 10)
	eptxt = net.JoinHostPort(s.Address, eptxt)
	wg := sync.WaitGroup{}
	wg.Add(4)
	wgrun := func(f func(s string)) func(string) {
		return func(s string) {
			defer wg.Done()
			f(s)
		}
	}
	go wgrun(s.startTCP)(cptxt)
	go wgrun(s.startTLS)(eptxt)
	go wgrun(s.startUDP)(cptxt)
	go wgrun(s.startDTLS)(eptxt)
	wg.Wait()
}

// todo: stop
func (s *Server) startTCP(addr string) {
	addr2, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	s.tcpListener, err = net.ListenTCP("tcp", addr2)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("start TCP server at %s", s.tcpListener.Addr())
	for {
		c, err := s.tcpListener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go s.streamServer(c)
	}
}

func (s *Server) startTLS(addr string) {
	conf := tls.Config{
		Certificates: []tls.Certificate{s.Cert},
	}
	fd, err := tls.Listen("tcp", addr, &conf)
	if err != nil {
		return
	}
	s.tlsListener = fd
	log.Printf("start TLS server at %s", fd.Addr())

	for {
		c, err := s.tlsListener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.streamServer(c)
	}
}

func (s *Server) startUDP(addr string) {
	addr2, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 4096)
	s.udpListener, err = net.ListenUDP("udp", addr2)
	log.Printf("start UDP server at %s", s.udpListener.LocalAddr())

	if err != nil {
		log.Fatal(err)
	}

	for {
		l, raddr, err := s.udpListener.ReadFrom(buf)
		if err != nil {
			log.Print(err)
		}
		s.datagramServer(raddr, buf[:l])
	}
}

func (s *Server) startDTLS(addr string) {
	addr2, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	s.dtlsListener, err = dtls.Listen("udp", addr2, &dtls.Config{
		Certificates: []tls.Certificate{s.Cert},
	})
	log.Printf("start DTLS server at %s", s.dtlsListener.Addr())

	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := s.dtlsListener.Accept()
		if err != nil {
			log.Print(err)
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 4096)
			l, err := c.Read(buf)
			if err != nil {
				log.Print(err)
				return
			}
			s.datagramServer(c.RemoteAddr(), buf[:l])
		}()
	}
}

func (s *Server) streamServer(conn net.Conn) {
	dontClose := false
	defer func() {
		if !dontClose {
			conn.Close()
		}
	}()
	req := socks6.Request{}
	_, err := socks6.ReadMessageFrom(&req, conn)
	errAtyp := false

	if err != nil {
		if errors.Is(err, socks6.ErrVersion) {
			if s.VersionErrorHandler == nil {
				conn.Write([]byte{6})
				log.Printf("%s version mismatch, recieved %d", conn.RemoteAddr(), req.Version)
			} else {
				dontClose = true
				s.VersionErrorHandler([]byte{req.Version}, conn)
			}
			return
		}
		if errors.Is(err, socks6.ErrAddressTypeNotSupport) {
			log.Print("unsupported address type")
			errAtyp = true
		} else {
			log.Print(err)
			return
		}
	}

	auth, rep := s.authenticator.Authenticate(req)

	err = socks6.WriteMessageTo(&rep, conn)
	if err != nil {
		log.Print(err)
		return
	}

	if !auth.Success {

		// TODO: slow path
		// TODO: wait client?
		return
	}

	log.Print("auth finish")
	if errAtyp {
		socks6.WriteMessageTo(
			&socks6.OperationReply{
				ReplyCode: socks6.OperationReplyAddressNotSupported,
			}, conn)
	}
	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientID) {
			err = socks6.WriteMessageTo(
				&socks6.OperationReply{
					ReplyCode: socks6.OperationReplyNotAllowedByRule,
				},
				conn,
			)
			if err != nil {
				log.Print(err)
			}
			return
		}
	}
	switch req.CommandCode {
	case socks6.CommandConnect:
		s.handleConnect(conn, req, auth)
	case socks6.CommandNoop:
		s.handleNoop(conn, req, auth)
	case socks6.CommandBind:
		s.handleBind(conn, req, auth)
	case socks6.CommandUdpAssociate:
		s.handleUDPAssociation(conn, req, auth)
	default:
		err = socks6.WriteMessageTo(
			&socks6.OperationReply{
				ReplyCode: socks6.OperationReplyCommandNotSupported,
			},
			conn,
		)
		if err != nil {
			log.Print(err)
		}
	}
}

func (s *Server) handleConnect(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	c, r, err := makeDestConn(req)
	if err != nil {
		oprep := socks6.OperationReply{
			ReplyCode:            socks6.OperationReplyServerFailure,
			RemoteLegStackOption: r,
			SessionID:            auth.SessionID,
			Endpoint:             socks6.NewEndpoint(":0"),
		}
		netErr, ok := err.(net.Error)
		if !ok {
			log.Print(err)
			socks6.WriteMessageTo(&oprep, conn)
			return
		}
		if netErr.Timeout() {
			oprep.ReplyCode = socks6.OperationReplyTimeout
			socks6.WriteMessageTo(&oprep, conn)
			return
		}
		opErr, ok := netErr.(*net.OpError)
		if !ok {
			socks6.WriteMessageTo(&oprep, conn)
			return
		}

		switch t := opErr.Err.(type) {
		case *os.SyscallError:
			errno, ok := t.Err.(syscall.Errno)
			if !ok {
				socks6.WriteMessageTo(&oprep, conn)
				return
			}
			switch errno {
			case syscall.ENETUNREACH, windows.WSAENETUNREACH:
				oprep.ReplyCode = socks6.OperationReplyNetworkUnreachable
			case syscall.EHOSTUNREACH, windows.WSAEHOSTUNREACH:
				oprep.ReplyCode = socks6.OperationReplyHostUnreachable
			case syscall.ECONNREFUSED, windows.WSAEREFUSED:
				oprep.ReplyCode = socks6.OperationReplyConnectionRefused
			case syscall.ETIMEDOUT, windows.WSAETIMEDOUT:
				oprep.ReplyCode = socks6.OperationReplyTimeout
			}
			socks6.WriteMessageTo(&oprep, conn)
			return
		}
		socks6.WriteMessageTo(&oprep, conn)
		return
	}
	defer c.Close()
	c.Write(req.InitialData)

	socks6.WriteMessageTo(
		&socks6.OperationReply{
			ReplyCode:            socks6.OperationReplySuccess,
			RemoteLegStackOption: r,
			SessionID:            auth.SessionID,
			Endpoint:             socks6.NewEndpoint(c.LocalAddr().String()),
		},
		conn,
	)
	relay(c, conn)
}

func (s *Server) handleNoop(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	socks6.WriteMessageTo(
		&socks6.OperationReply{
			ReplyCode: socks6.OperationReplySuccess,
			SessionID: auth.SessionID,
			Endpoint:  socks6.NewEndpoint("0.0.0.0:0"),
		},
		conn,
	)
}

func (s *Server) handleBind(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	l, r, err := makeDestListener(req)
	log.Print(l.Addr().String())
	if err != nil {
		log.Print(err)
		// todo reply err
		return
	}

	// find corresponding backlog conn
	reqAddr := req.Endpoint.String()
	if backlogged, ok := s.backloggedConnections[reqAddr]; ok {
		if !socks6.ByteArrayEqual(auth.SessionID, backlogged.sessionId) {
			return
		}
		backlogged.clientConn <- conn
		<-backlogged.done
	}

	backloggedBind := req.RemoteLegStackOption.Backlog != nil
	nBacklog := uint16(0)
	if backloggedBind {
		nBacklog = *req.RemoteLegStackOption.Backlog
		r.Backlog = &nBacklog
	}

	// write op reply 1
	socks6.WriteMessageTo(
		&socks6.OperationReply{
			ReplyCode:            socks6.OperationReplySuccess,
			SessionID:            auth.SessionID,
			RemoteLegStackOption: r,
			Endpoint:             socks6.NewEndpoint(l.Addr().String()),
		},
		conn,
	)
	if !backloggedBind {
		s.handleBindNoBacklog(l, conn, req, auth)
	} else {
		s.handleBindBacklog(l, nBacklog, conn, req, auth)
	}
}
func (s *Server) handleBindNoBacklog(l net.Listener, conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	defer l.Close()
	rconn, err := l.Accept()
	if err != nil {
		return
	}
	defer rconn.Close()

	// op reply 2
	socks6.WriteMessageTo(
		&socks6.OperationReply{
			ReplyCode: socks6.OperationReplySuccess,
			SessionID: auth.SessionID,
			Endpoint:  socks6.NewEndpoint(rconn.RemoteAddr().String()),
		},
		conn,
	)
	relay(conn, rconn)
}
func (s *Server) handleBindBacklog(
	l net.Listener,
	nBacklog uint16,
	conn net.Conn,
	req socks6.Request,
	auth AuthenticationResult) {
	// not tested

	// watch control conn eof
	ctx, eof := context.WithCancel(context.Background())
	go func() {
		drain(conn)
		// clear backlogged conn
		for k, v := range s.backloggedConnections {
			if socks6.ByteArrayEqual(v.sessionId, auth.SessionID) && len(v.sessionId) > 0 {
				delete(s.backloggedConnections, k)
			}
		}
		// close listener
		l.Close()
		// cancel ctx
		eof()
	}()
	// emulated backlog
	sem := semaphore.NewWeighted(int64(nBacklog))
	for {
		// wait other conn accepted
		err := sem.Acquire(ctx, 1)
		if err != nil {
			return
		}
		rconn, err := l.Accept()
		if err != nil {
			return
		}
		defer rconn.Close()
		// put bci info
		raddr := rconn.RemoteAddr().String()
		bci := backloggedConnectionInfo{
			sessionId:  auth.SessionID,
			clientConn: make(chan net.Conn),
			done:       make(chan int),
			remoteAddr: raddr,
		}
		s.backloggedConnections[raddr] = bci
		// send op reply 2
		go socks6.WriteMessageTo(
			&socks6.OperationReply{
				ReplyCode: socks6.OperationReplySuccess,
				SessionID: auth.SessionID,
				Endpoint:  socks6.NewEndpoint(raddr),
			},
			conn,
		)
		var conn2 net.Conn
		select {
		case <-ctx.Done():
			return
		// wait accept bind
		case conn2 = <-bci.clientConn:
			sem.Release(1)
			delete(s.backloggedConnections, raddr)
			defer func() {
				bci.done <- 1
			}()
			relay(rconn, conn2)
		}
	}
}

func (s *Server) handleUDPAssociation(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	desired := req.Endpoint.String()
	var c *net.UDPConn
	r := socks6.StackOptionData{}
	desc, ok := s.reservedPorts[desired]
	if ok {
		if socks6.ByteArrayEqual(auth.SessionID, desc.sessionId) {
			c = desc.conn
		}
	} else {
		cc, rr, err := makeDestUDP(req)
		c = cc
		r = rr
		if err != nil {
			// report error
			return
		}
	}
	defer c.Close()
	socks6.WriteMessageTo(
		&socks6.OperationReply{
			ReplyCode:            socks6.OperationReplySuccess,
			RemoteLegStackOption: r,
			SessionID:            auth.SessionID,
			Endpoint:             socks6.NewEndpoint(c.LocalAddr().String()),
		},
		conn,
	)
	b := make([]byte, 8)
	_, err := rand.Read(b)
	// todo unique associd
	assocId := binary.BigEndian.Uint64(b)
	if err != nil {
		return
	}
	socks6.WriteMessageTo(
		&socks6.UDPHeader{
			Type:          socks6.UDPMessageAssociationInit,
			AssociationID: assocId,
		},
		conn,
	)
	assoc := udpAssociationInfo{
		conn: *c,
	}
	s.udpAssociations[assocId] = &assoc
	assoc.received.Lock()
	// read tcp uplink
	go func() {
		for {
			h := socks6.UDPHeader{}
			_, err := socks6.ReadMessageFrom(&h, conn)
			if err != nil {
				log.Print(err)
				return
			}
			switch h.Type {
			case socks6.UDPMessageDatagram:
				if assoc.tcp {
					// assoc to conn

				} else if assoc.dgramNet == "" {
					// not assoc yet
					assoc.tcp = true
					assoc.downlink = func(b []byte) (int, error) {
						return conn.Write(b)
					}
					assoc.received.Unlock()
				} else {
					// another assoc
					continue
				}
				if assocId != h.AssociationID {
					continue
				}
				raddrStr := h.Endpoint.String()
				raddr, err := net.ResolveUDPAddr("udp", raddrStr)
				if err != nil {
					continue
				}
				c.WriteTo(h.Data, raddr)
			default:
			}
		}
	}()

	// send assoc confirm
	assoc.received.Lock()
	socks6.WriteMessageTo(
		&socks6.UDPHeader{
			Type:          socks6.UDPMessageAssociationAck,
			AssociationID: assocId,
		},
		conn,
	)
	go func() {
		buf := make([]byte, 4096)
		for {
			l, raddr, err := c.ReadFrom(buf)
			if err != nil {
				log.Print(err)
			}
			h := socks6.UDPHeader{
				Type:          socks6.UDPMessageDatagram,
				AssociationID: assocId,
				Endpoint:      socks6.NewEndpoint(raddr.String()),
				Data:          buf[:l],
			}
			b, err := socks6.WriteMessage(&h)

			if err != nil {
				log.Print(err)
			}
			_, err = assoc.downlink(b)
			if err != nil {
				log.Print(err)
			}
		}
	}()
	if assoc.tcp {
		// todo wait for conn close
		time.Sleep(1 * time.Hour)
	} else {
		drain(conn)
	}
}

func (s *Server) datagramServer(addr net.Addr, buf []byte) {
	h := socks6.UDPHeader{}
	r := bytes.NewReader(buf)
	_, err := socks6.ReadMessageFrom(&h, r)
	if err != nil {
		return
	}
	assocId := h.AssociationID
	assoc, ok := s.udpAssociations[assocId]
	// no assoc
	if !ok {
		return
	}
	// already assoc on tcp
	if assoc.tcp {
		return
	}

	raddr, err := net.ResolveUDPAddr("udp", h.Endpoint.String())
	if err != nil {
		return
	}
	// TODO udp & dtls
	if assoc.dgramNet != "" {
		if assoc.dgramLocal.String() != s.udpListener.LocalAddr().String() ||
			assoc.dgramRemote.String() != addr.String() {
			// another udp assoc
			return
		}
		assoc.conn.WriteTo(h.Data, raddr)
		return
	} else {
		assoc.dgramNet = "udp"
		assoc.dgramLocal = s.udpListener.LocalAddr()
		assoc.dgramRemote = addr
		_, err = assoc.conn.WriteTo(h.Data, raddr)
		if err != nil {
			log.Print(err)
		}
		assoc.received.Unlock()
		assoc.downlink = func(b []byte) (int, error) {
			return s.udpListener.WriteTo(b, addr)
		}
	}

}

func drain(conn net.Conn) error {
	b := make([]byte, 32)
	for {
		_, err := conn.Read(b)
		if err != nil {
			return err
		}
	}
}

// relay copies between left and right bidirectionally
// copy pasted from go-shadowsocks2
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

func makeDestConn(req socks6.Request) (net.Conn, socks6.StackOptionData, error) {
	rso := req.RemoteLegStackOption
	supported := socks6.StackOptionData{}

	d := net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(
				func(fd uintptr) {
					supported = setsocks6optTcpClient(fd, rso)
				})
			return nil
		},
	}
	if rso.HappyEyeball != nil && req.Endpoint.AddressType == socks6.AddressTypeDomainName {
		if !*(rso.HappyEyeball) {
			f := false
			// rfc8305 is based on rfc6555
			d.FallbackDelay = -1
			supported.HappyEyeball = &f
		} else {
			t := true
			supported.HappyEyeball = &t
		}
	}
	c, e := d.Dial("tcp", req.Endpoint.String())
	return c, supported, e
}

func makeDestListener(req socks6.Request) (net.Listener, socks6.StackOptionData, error) {
	supported := socks6.StackOptionData{}
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			c.Control(
				func(fd uintptr) {
					supported = setsocks6optTcpServer(fd, req.RemoteLegStackOption)
				})
			return nil
		},
	}
	l, err := cfg.Listen(context.Background(), "tcp", req.Endpoint.String())
	return l, supported, err
}

func makeDestUDP(req socks6.Request) (*net.UDPConn, socks6.StackOptionData, error) {
	ep := req.Endpoint.String()
	addr, err := net.ResolveUDPAddr("udp", ep)
	op := socks6.StackOptionData{}
	if err != nil {
		log.Print(err)
		return nil, op, err
	}
	// todo mcast?
	uc, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Print(err)
		return nil, op, err
	}
	op = prepareDestUDP(uc, req.RemoteLegStackOption)
	return uc, op, nil
}

func prepareDestUDP(conn *net.UDPConn, opt socks6.StackOptionData) socks6.StackOptionData {
	raw, _ := conn.SyscallConn()
	op := socks6.StackOptionData{}

	raw.Control(
		func(fd uintptr) {
			op = setsocks6optUdp(fd, opt)
		})
	return op
}
