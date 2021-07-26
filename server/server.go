package server

import (
	_ "crypto/tls"
	"log"
	"net"
	"syscall"

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
	req := socks6.Request{}
	buf := make([]byte, 0, 64)
	p := 0
	for {
		requiredSize := req.BufferSize(buf)
		if requiredSize > len(buf) {
			buf = append(buf, make([]byte, requiredSize-len(buf))...)
		}
		if requiredSize > p {
			expectRead := requiredSize - p
			actualRead, err := conn.Read(buf[p:requiredSize])
			p += actualRead
			if err != nil {
				log.Println(err)
				conn.Close()
				return
			}
			if actualRead != expectRead {
				log.Println("unexpected read size")
				conn.Close()
				return
			}
			if buf[0] != 6 {
				log.Println("unexpected version", buf[0])
				conn.Write([]byte{6})
				conn.Close()
				return
			}
		} else {
			l, err := req.Deserialize(buf[:p])
			if err != nil {
				log.Println(err)
				conn.Close()
				return
			}
			if l != p {
				log.Println("unexpected read size")
				conn.Close()
				return
			}
			break
		}
	}
	ok, rep, _, cid := s.authenticator.Authenticate(req)
	log.Println(cid)
	buf = make([]byte, 1024)
	l, err := rep.Serialize(buf)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(buf[:l])
	if err != nil {
		log.Print(err)
		return
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
			_ = socks6.OperationReply{
				ReplyCode: socks6.OperationReplyNotAllowedByRule,
			}
			return
		}
	}
	if req.CommandCode == socks6.CommandConnect {
		c, r, err := makeDestConn(req)
		if err != nil {
			// report error
			return
		}

		c.Write(req.InitialData)
		// reply,start proxy
		_ = socks6.OperationReply{
			ReplyCode:            socks6.OperationReplySuccess,
			RemoteLegStackOption: r,
		}
	}
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
