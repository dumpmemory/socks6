package server

import (
	_ "crypto/tls"
	"log"
	"net"

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
		s.handleConn(c)
	}()
}

func (s *Server) handleConn(conn *net.TCPConn) {
	req := socks6.Request{}
	buf := make([]byte, 0, 64)
	p := 0
	for {
		requiredSize := req.BufferSize(buf)
		if requiredSize > p {
			expectRead := requiredSize - p
			actualRead, err := conn.Read(buf[p:requiredSize])
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
		conn.Close()
		return
	}
	if !ok {
		// TODO: slow path
		// TODO: wait client?
		conn.Close()
		return
	}

	// TODO: operation reply

}
