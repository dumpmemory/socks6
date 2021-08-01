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

	tcpListener  *net.TCPListener
	tlsListener  net.Listener
	udpListener  *net.UDPConn
	dtlsListener net.Listener

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
	// s.authenticator.MethodSelector.AddMethod(NoneAuthentication{})
	s.udpAssociations = map[uint64]*udpAssociationInfo{}
	s.backloggedConnections = map[string]backloggedConnectionInfo{}

	cptxt := strconv.FormatUint(uint64(s.CleartextPort), 10)
	cptxt = net.JoinHostPort(s.Address, cptxt)
	eptxt := strconv.FormatUint(uint64(s.EncryptedPort), 10)
	eptxt = net.JoinHostPort(s.Address, eptxt)

	s.startTCP(cptxt)
	s.startTLS(eptxt)
	s.startUDP(cptxt)
	s.startDTLS(eptxt)
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

	go func() {
		for {
			c, err := s.tcpListener.AcceptTCP()
			if err != nil {
				log.Fatal(err)
			}
			go s.handleConn(c)
		}
	}()
}

const (
	debugKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAreOEK/j2T4xW1LLjtH9LCEw30kb6MYPdKwT9a0kYTeS1v3jz
aP9kmTaL+FOLfBd6xZ//4QIXONpomVvqWCZbs+XQYBKaYeL1jSxCuK5/K6ZNcUOD
PZdShacdS4O1XwLUQmW0PALf1Beb1Ma7wwFYan2qdWCOjKo3HvfbbUKTOHD5iWbs
SRqcD5ekAcs5t4eUuDmSJZc00RcV/rwRbXgyCwvU9xeBA3AhADdRdbU/KeUq1VA3
/UTeWIxCabvu7ebj+WuMqy6UrQtDJCNlezjJRh6UcpwKhTMhm7+zNCEd9oCAJKNt
nvVF2d+qVMlrMt/2sA0ecOlbHNndmMNqTYKoSwIDAQABAoIBAQCJp8fVK6SJurZu
cSNTm0WhzvyNyUR8+D+Ys72ONfI4j6rVZgGDiFJx+714m2KbnNbDJfNhg88wYa5W
YW411D/aPT7lHzT58rqixHwZSYJA4skBtglqM6XPSkklo6FsEohH+81fiIL6mqnx
GlY/fIwq2Uqc2xBeCM3UBTC+4Oo8zdwyT4srTlJWXGLkFBnGcka2QXAIyRyznkND
kzLNbKx/XuoHK0CYHW5ChIjmpmjvQZt6H8rAoCeUGKCiNN6SkMAWzg0nT1XtaYnj
+PT4zUHI/iAitoMHacsrgDuXVnA0IiRFWtegcb4ixlq8hFkxYhkNtxwfmhoOkpOW
nylSNtIZAoGBAN3yKNzzYcUdOaRbKLDmJfikfK2ZSveL/ha5S0oU4UiBsrlDpeCX
B7Y4gVl84nPlwpXDhPVvUyobS84X9/Q7iBAJJh4M5h34D3L1bi+JJH3/6GaNCeM5
d/MUcQocbKpziuuefq36rj9n3j+HfvzRckDgbylmb7jxiywoUc5/EueVAoGBAMiR
tle3xTyNSbodDguSL8MLzr5vEiE6rm4fZjKSXl1hZv8Z1yrSInxCBmRQo4tm+pr4
6yL48kfGkb6Xo39XH1qW/jRmnHDIM2Hw8fK51M44qEkzDVdfKyUHRzRIjNDRUf+4
gM8orLMuJAd+Uhh+iPNgx8lgy745AIgsEIUvddhfAoGBAK0a0Wo7XVcrCyk4fE00
xArg5+lSNVlL07qPfLxj+q3dkrLSo06/HSGvgpt0Pv8cBZ9fZpUy5c9iiMZOhXL0
95NiP1uSvexD7HDCIdVrho3LicxqVnrl+Lsbh2rWbp6nDYPmE3HIoh0L+xjbqlyv
Uwhsw+arYZoCsoSXUe7Xx7vdAoGAcNcBtlIOpmV68Dl+eGYTdvGCrEMC+Szxi8Ug
kx0j9/dfoe/gzReSDUR8Ih34FOqn3V5js7ZJYLZHsunPM0pJuoaul76PDyijN9v9
0yhXoHnhu+T8AYbqWBfDKJgUmTranjsoRORGXTx9SrX37A3scLinThWmKuwY74OS
+8taypMCgYA4Lqh4/GCISKBF+jvVpTO9hiwTFuuKM+yeDTfcypKCqNNJRoCv0r+T
mCe9sLh2AsQLwQvBvue07evyYrJaIc1s/toWqjqRhyHgboihPDgwswvDmjnG3RLZ
3zu/D3TJ+GsgJhAGPMylJgbJuUY7oOtUCHG/4RoUNQ31zRyj4Z56Hw==
-----END RSA PRIVATE KEY-----`

	debugPem = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUTQsfaHflfPj5E48wWX10KirQm1gwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTA3MjcxMzM5MTlaFw0zMTA3
MjUxMzM5MTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCt44Qr+PZPjFbUsuO0f0sITDfSRvoxg90rBP1rSRhN
5LW/ePNo/2SZNov4U4t8F3rFn//hAhc42miZW+pYJluz5dBgEpph4vWNLEK4rn8r
pk1xQ4M9l1KFpx1Lg7VfAtRCZbQ8At/UF5vUxrvDAVhqfap1YI6Mqjce99ttQpM4
cPmJZuxJGpwPl6QByzm3h5S4OZIllzTRFxX+vBFteDILC9T3F4EDcCEAN1F1tT8p
5SrVUDf9RN5YjEJpu+7t5uP5a4yrLpStC0MkI2V7OMlGHpRynAqFMyGbv7M0IR32
gIAko22e9UXZ36pUyWsy3/awDR5w6Vsc2d2Yw2pNgqhLAgMBAAGjUzBRMB0GA1Ud
DgQWBBRGe1mLiI1nILnyMHyS0+xXDMAwjDAfBgNVHSMEGDAWgBRGe1mLiI1nILny
MHyS0+xXDMAwjDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAK
79xS4dA/NhJ77/fF44GRH3anRTw38na8kEzhqjrMuHwWdtgObtP6gPSHJiSG268n
lKsQrdhzYfDcMFVxnjW4E3H9OVpvON2VxXU6m0lBNpOEnUGf92ZHlmCNzkTFsDVx
0WBmVLmfJZ3Ic7B2bRKLl1AKl1zXkhMpYO7xlnOzIdjCHgu68qfpikP/HkHeUlhw
w0d6vd+Vuhku06+R5Wf6IGuLFyAFMSqjzxsTrZJ5QfCpiT5N8Sp5xv7SfUWG+aCH
oGGJ+KZGw88sgiJhgZ7g7lfB1/AbjomhvUgqBzY74J0d+k1FUqJLNWZ+tF8U/4h2
fQIXRNDBdXLIdOAl2+PZ
-----END CERTIFICATE-----`
)

func (s *Server) startTLS(addr string) {
	cert, _ := tls.X509KeyPair([]byte(debugPem), []byte(debugKey))
	conf := tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	fd, err := tls.Listen("tcp", addr, &conf)
	if err != nil {
		return
	}
	s.tlsListener = fd

	go func() {
		for {
			c, err := s.tlsListener.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go s.handleConn(c)
		}
	}()
}

func (s *Server) startUDP(addr string) {
	addr2, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 4096)
	s.udpListener, err = net.ListenUDP("udp", addr2)
	if err != nil {
		log.Fatal(err)
	}
	for {
		l, raddr, err := s.udpListener.ReadFrom(buf)
		if err != nil {
			log.Print(err)
		}
		s.handleUDP(raddr, buf[:l])
	}
}

func (s *Server) startDTLS(addr string) {
	addr2, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	cert, _ := tls.X509KeyPair([]byte(debugPem), []byte(debugKey))
	s.dtlsListener, err = dtls.Listen("udp", addr2, &dtls.Config{
		Certificates: []tls.Certificate{cert},
	})
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
			s.handleUDP(c.RemoteAddr(), buf[:l])
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	dontClose := false
	defer func() {
		if !dontClose {
			conn.Close()
		}
	}()
	req := socks6.Request{}
	l, err := socks6.ReadMessageFrom(&req, conn)
	log.Print(l)
	log.Print(err)
	log.Print(req)
	if err != nil {
		// todo fallback
		return
	}

	auth, rep := s.authenticator.Authenticate(req)

	log.Println(auth.ClientID)
	err = socks6.WriteMessageTo(&rep, conn)
	if err != nil {
		log.Fatal(err)
	}

	if !auth.Success {
		// TODO: slow path
		// TODO: wait client?
		return
	}

	log.Print("auth finish")

	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientID) {
			socks6.WriteMessageTo(
				&socks6.OperationReply{
					ReplyCode: socks6.OperationReplyNotAllowedByRule,
				},
				conn,
			)
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
		socks6.WriteMessageTo(
			&socks6.OperationReply{
				ReplyCode: socks6.OperationReplyServerFailure,
			},
			conn,
		)
	}
}

func (s *Server) handleConnect(conn net.Conn, req socks6.Request, auth AuthenticationResult) {
	c, r, err := makeDestConn(req)
	if err != nil {
		log.Print(err)
		// report error
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

func (s *Server) handleUDP(addr net.Addr, buf []byte) {
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
