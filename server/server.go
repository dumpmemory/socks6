package server

import (
	_ "crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	_ "github.com/pion/dtls/v2"
	"github.com/studentmain/socks6"
)

type Server struct {
	tcpListener  *net.TCPListener
	tlsListener  *net.Listener
	udpListener  *net.UDPConn
	dtlsListener *net.Listener

	udpAssociations map[uint64]bool
	authenticator   DefaultAuthenticator

	Rule func(op byte, dst, src net.Addr, cid ClientID) bool
}

func (s *Server) Start() {
	s.startTCP(":10888")
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
		c, err := s.tcpListener.AcceptTCP()
		if err != nil {
			log.Fatal(err)
		}
		go s.handleConn(c)
	}()
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer conn.Close()
	mrw := socks6.MessageReaderWriter{}
	req := socks6.Request{}
	l, err := mrw.DeserializeFrom(&req, conn)
	log.Print(l)
	log.Print(err)
	log.Print(req)
	if err != nil {
		return
	}

	ok, rep, _, cid := s.authenticator.Authenticate(req)
	log.Println(cid)
	err = mrw.SerializeTo(&rep, conn)
	if err != nil {
		log.Fatal(err)
	}

	if !ok {
		// TODO: slow path
		// TODO: wait client?
		return
	}

	// TODO: operation reply
	log.Print("auth finish")

	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), cid) {
			mrw.SerializeTo(
				&socks6.OperationReply{
					ReplyCode: socks6.OperationReplyNotAllowedByRule,
				},
				conn,
			)
			return
		}
	}
	if req.CommandCode == socks6.CommandConnect {
		c, r, err := makeDestConn(req)
		if err != nil {
			// report error
			return
		}
		defer c.Close()

		c.Write(req.InitialData)
		// reply,start proxy
		go mrw.SerializeTo(
			&socks6.OperationReply{
				ReplyCode:            socks6.OperationReplySuccess,
				RemoteLegStackOption: r,
			},
			conn,
		)
		relay(c, conn)
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
