package server

import (
	"context"
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
	"golang.org/x/sync/semaphore"
)

type Server struct {
	tcpListener  *net.TCPListener
	tlsListener  *net.Listener
	udpListener  *net.UDPConn
	dtlsListener *net.Listener

	udpAssociations       map[uint64]bool
	authenticator         DefaultAuthenticator
	backloggedConnections map[string]backloggedConnectionInfo

	Rule func(op byte, dst, src net.Addr, cid ClientID) bool
}

type backloggedConnectionInfo struct {
	sessionId  []byte
	clientConn chan net.Conn
	done       chan int
	remoteAddr string
}

func (s *Server) Start() {
	s.authenticator.MethodSelector.AddMethod(NoneAuthentication{})
	s.startTCP(net.JoinHostPort("", "10888"))
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

	auth, rep := s.authenticator.Authenticate(req)

	log.Println(auth.ClientID)
	err = mrw.SerializeTo(&rep, conn)
	if err != nil {
		log.Fatal(err)
	}

	if !auth.Success {
		// TODO: slow path
		// TODO: wait client?
		return
	}

	// TODO: operation reply
	log.Print("auth finish")

	if s.Rule != nil {
		if !s.Rule(req.CommandCode, req.Endpoint, conn.RemoteAddr(), auth.ClientID) {
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
				SessionID:            auth.SessionID,
			},
			conn,
		)
		relay(c, conn)
	} else if req.CommandCode == socks6.CommandNoop {
		mrw.SerializeTo(
			&socks6.OperationReply{
				ReplyCode: socks6.OperationReplySuccess,
				SessionID: auth.SessionID,
			},
			conn,
		)
	} else if req.CommandCode == socks6.CommandBind {
		l, r, err := makeDestListener(req)
		if err != nil {
			log.Print(err)
			// todo reply err
			return
		}

		// find corresponding backlog conn
		reqAddr := req.Endpoint.String()
		if backlogged, ok := s.backloggedConnections[reqAddr]; ok {
			if false /*auth.SessionID == backlogged.sessionId*/ {
				return
			}
			backlogged.clientConn <- conn
			<-backlogged.done
		}

		backloggedBind := req.RemoteLegStackOption.Backlog != nil
		nBacklog := *req.RemoteLegStackOption.Backlog
		if backloggedBind {
			r.Backlog = &nBacklog
		}
		mrw.SerializeTo(
			&socks6.OperationReply{
				ReplyCode:            socks6.OperationReplySuccess,
				SessionID:            auth.SessionID,
				RemoteLegStackOption: r,
			},
			conn,
		)
		if !backloggedBind {
			defer l.Close()
			rconn, err := l.Accept()
			if err != nil {
				return
			}
			defer rconn.Close()
			raddr := rconn.RemoteAddr()
			ep := socks6.Endpoint{}
			ep.ParseEndpoint(raddr.String())
			go mrw.SerializeTo(
				&socks6.OperationReply{
					ReplyCode: socks6.OperationReplySuccess,
					SessionID: auth.SessionID,
					Endpoint:  ep,
				},
				conn,
			)
			relay(conn, rconn)
		} else {
			// watch control conn eof
			ctx, eof := context.WithCancel(context.Background())
			go func() {
				drain(conn)
				// clear backlogged conn
				for k, v := range s.backloggedConnections {
					if /*v.sessionId == auth.SessionID*/ true && len(v.sessionId) > 0 {
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
				err = sem.Acquire(ctx, 1)
				rconn, err := l.Accept()
				if err != nil {
					return
				}
				defer rconn.Close()
				if err != nil {
					return
				}
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
				ep := socks6.Endpoint{}
				ep.ParseEndpoint(raddr)
				go mrw.SerializeTo(
					&socks6.OperationReply{
						ReplyCode: socks6.OperationReplySuccess,
						SessionID: auth.SessionID,
						Endpoint:  ep,
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
	l, err := cfg.Listen(context.Background(), "tcp", "")
	return l, supported, err
}
