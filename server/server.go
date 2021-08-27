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
	cancel   sync.Mutex

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
	req, err := socks6.ParseRequestFrom(conn)
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
	initDataLen := uint16(0)
	amao, ok := req.Options.GetData(socks6.OptionKindAuthenticationMethodAdvertisement)
	if ok {
		amaod := amao.(socks6.AuthenticationMethodAdvertisementOptionData)
		initDataLen = amaod.InitialDataLength
	}
	initialData := make([]byte, initDataLen)
	if ok {
		_, err = io.ReadFull(conn, initialData)
		if err != nil {
			log.Print(err)
			return
		}
	}

	auth, rep := s.authenticator.Authenticate(*req)

	_, err = conn.Write(rep.Marshal())
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
		conn.Write((&socks6.OperationReply{
			ReplyCode: socks6.OperationReplyAddressNotSupported,
		}).Marshal())
	}
	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientID) {
			_, err = conn.Write((&socks6.OperationReply{
				ReplyCode: socks6.OperationReplyAddressNotSupported,
			}).Marshal())
			if err != nil {
				log.Print(err)
			}
			return
		}
	}
	switch req.CommandCode {
	case socks6.CommandConnect:
		s.handleConnect(conn, *req, auth, initialData)
	case socks6.CommandNoop:
		s.handleNoop(conn, *req, auth)
	case socks6.CommandBind:
		s.handleBind(conn, *req, auth)
	case socks6.CommandUdpAssociate:
		s.handleUDPAssociation(conn, *req, auth)
	default:
		_, err = conn.Write((&socks6.OperationReply{
			ReplyCode: socks6.OperationReplyCommandNotSupported,
		}).Marshal())
		if err != nil {
			log.Print(err)
		}
	}
}

func setSessionId(oprep *socks6.OperationReply, id []byte) {
	if id == nil {
		return
	}
	oprep.Options.Add(socks6.Option{
		Kind: socks6.OptionKindSessionID,
		Data: socks6.SessionIDOptionData{
			ID: id,
		},
	})
}

func (s *Server) handleConnect(conn net.Conn, req socks6.Request, auth AuthenticationResult, initialData []byte) {
	c, r, err := makeDestConn(req)
	code := getReplyCode(err)
	oprep := socks6.OperationReply{
		ReplyCode: code,
		Endpoint:  socks6.NewAddrP(":0"),
	}
	// todo client leg options
	oprep.Options.AddMany(r.GetOptions(false, true))
	setSessionId(&oprep, auth.SessionID)

	if code != socks6.OperationReplySuccess {
		conn.Write(oprep.Marshal())
		return
	}

	defer c.Close()
	c.Write(initialData)
	oprep.Endpoint = socks6.NewAddrP(c.LocalAddr().String())
	conn.Write(oprep.Marshal())
	relay(c, conn)
}

func (s *Server) handleNoop(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	oprep := socks6.OperationReply{
		ReplyCode: socks6.OperationReplySuccess,
		Endpoint:  socks6.NewAddrP("0.0.0.0:0"),
	}
	setSessionId(&oprep, auth.SessionID)
	conn.Write(oprep.Marshal())
}

func (s *Server) handleBind(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	l, r, err := makeDestListener(req)
	code := getReplyCode(err)
	oprep := socks6.OperationReply{
		ReplyCode: code,
		Endpoint:  socks6.NewAddrP(":0"),
	} // todo client leg options
	oprep.Options.AddMany(r.GetOptions(false, true))
	setSessionId(&oprep, auth.SessionID)

	if code != socks6.OperationReplySuccess {
		conn.Write(oprep.Marshal())
		return
	}
	log.Print(l.Addr().String())
	oprep.Endpoint = socks6.NewAddrP(l.Addr().String())

	// find corresponding backlog conn
	reqAddr := req.Endpoint.String()
	if backlogged, ok := s.backloggedConnections[reqAddr]; ok {
		if !socks6.ByteArrayEqual(auth.SessionID, backlogged.sessionId) {
			return
		}
		backlogged.clientConn <- conn
		<-backlogged.done
	}

	rso := GetStackOptionInfo(req.Options, false)
	nBacklog := uint16(0)
	nBacklogI, backloggedBind := rso[socks6.StackOptionTCPBacklog]
	if backloggedBind {
		nBacklog = nBacklogI.(uint16)
		r[socks6.StackOptionTCPBacklog] = nBacklog
	}

	// write op reply 1
	conn.Write(oprep.Marshal())
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
	oprep := socks6.OperationReply{
		ReplyCode: socks6.OperationReplySuccess,
		Endpoint:  socks6.NewAddrP(rconn.RemoteAddr().String()),
	}
	setSessionId(&oprep, auth.SessionID)

	conn.Write(oprep.Marshal())
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
		oprep := socks6.OperationReply{
			ReplyCode: socks6.OperationReplySuccess,
			Endpoint:  socks6.NewAddrP(raddr),
		}
		setSessionId(&oprep, auth.SessionID)
		conn.Write(oprep.Marshal())
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
	var remoteConn *net.UDPConn
	appliedRemoteOption := StackOptionInfo{}
	reserveInfo, reserved := s.reservedPorts[desired]
	var oprep socks6.OperationReply

	if reserved {
		// 8.1.9 assoc to prev reserved port
		if socks6.ByteArrayEqual(auth.SessionID, reserveInfo.sessionId) {
			rso := StackOptionInfo{}
			ops := getStackOptions(req.Options, false)
			rso.AddMany(ops)

			remoteConn = reserveInfo.conn
			appliedRemoteOption = prepareDestUDP(remoteConn, rso)
			oprep = socks6.OperationReply{
				ReplyCode: socks6.OperationReplySuccess,
				Endpoint:  socks6.NewAddrP(remoteConn.LocalAddr().String()),
			}
			// todo client leg options
			oprep.Options.AddMany(appliedRemoteOption.GetOptions(false, true))

		} else {
			// wrong assoc, fail
			oprep = socks6.OperationReply{
				ReplyCode: socks6.OperationReplyNotAllowedByRule,
				Endpoint:  socks6.NewAddrP(":0"),
			}
		}
	} else {
		// normal conn
		cc, rr, err := makeDestUDP(req)
		remoteConn = cc
		appliedRemoteOption = rr
		oprep = socks6.OperationReply{
			ReplyCode: getReplyCode(err),
			Endpoint:  socks6.NewAddrP(remoteConn.LocalAddr().String()),
		}
		// todo client leg options
		oprep.Options.AddMany(appliedRemoteOption.GetOptions(false, true))
	}
	setSessionId(&oprep, auth.SessionID)

	// write operational reply
	conn.Write(oprep.Marshal())
	if oprep.ReplyCode != socks6.OperationReplySuccess {
		return
	}

	// make association
	defer remoteConn.Close()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	// todo unique associd?
	assocId := binary.BigEndian.Uint64(b)
	if err != nil {
		return
	}

	// write associd
	conn.Write((&socks6.UDPHeader{
		Type:          socks6.UDPMessageAssociationInit,
		AssociationID: assocId,
	}).Marshal())

	assoc := udpAssociationInfo{
		conn: *remoteConn,
	}
	s.udpAssociations[assocId] = &assoc
	// first datagram havent recv yet
	assoc.received.Lock()

	// read tcp uplink
	go func() {
		for {
			h, err := socks6.ParseUDPHeaderFrom(conn)
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
				remoteConn.WriteTo(h.Data, raddr)
			default:
			}
		}
	}()

	// send assoc confirm
	assoc.received.Lock()
	conn.Write((&socks6.UDPHeader{
		Type:          socks6.UDPMessageAssociationAck,
		AssociationID: assocId,
	}).Marshal())
	go func() {
		buf := make([]byte, 4096)
		for {
			l, raddr, err := remoteConn.ReadFrom(buf)
			if err != nil {
				log.Print(err)
			}
			h := socks6.UDPHeader{
				Type:          socks6.UDPMessageDatagram,
				AssociationID: assocId,
				Endpoint:      socks6.NewAddrP(raddr.String()),
				Data:          buf[:l],
			}

			if err != nil {
				log.Print(err)
			}
			_, err = assoc.downlink(h.Marshal())
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

func handleUDPOverTCP(conn net.Conn, assoc *udpAssociationInfo) {
	// todo a total rewrite of udp?
	defer func() {
		log.Print("udp assoc uplink off")
		assoc.cancel.Unlock()
	}()
	for {
		_, err := socks6.ParseUDPHeaderFrom(conn)
		// todo: when udp, ignore parse error
		if err != nil {
			log.Print(err)
			return
		}
	}
}

func getReplyCode(err error) byte {
	if err == nil {
		return socks6.OperationReplySuccess
	}
	netErr, ok := err.(net.Error)
	if !ok {
		log.Print(err)
		return socks6.OperationReplyServerFailure
	}
	if netErr.Timeout() {
		return socks6.OperationReplyTimeout
	}
	opErr, ok := netErr.(*net.OpError)
	if !ok {
		return socks6.OperationReplyServerFailure
	}

	switch t := opErr.Err.(type) {
	case *os.SyscallError:
		errno, ok := t.Err.(syscall.Errno)
		if !ok {
			return socks6.OperationReplyServerFailure
		}
		switch convertErrno(errno) {
		case syscall.ENETUNREACH:
			return socks6.OperationReplyNetworkUnreachable
		case syscall.EHOSTUNREACH:
			return socks6.OperationReplyHostUnreachable
		case syscall.ECONNREFUSED:
			return socks6.OperationReplyConnectionRefused
		case syscall.ETIMEDOUT:
			return socks6.OperationReplyTimeout
		default:
			return socks6.OperationReplyServerFailure
		}
	}
	return socks6.OperationReplyServerFailure
}

func (s *Server) datagramServer(addr net.Addr, buf []byte) {
	r := bytes.NewReader(buf)
	h, err := socks6.ParseUDPHeaderFrom(r)
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
