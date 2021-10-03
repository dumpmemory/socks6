package socks6

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/lg"
)

type Server struct {
	Address       string
	CleartextPort uint16
	EncryptedPort uint16

	Cert tls.Certificate

	worker ServerWorker

	// listeners

	tcp  net.Listener
	udp  net.PacketConn
	tls  net.Listener
	dtls net.Listener
}

func (s *Server) Start(ctx context.Context) {
	s.worker = *NewServerWorker()

	if s.CleartextPort != 0 {
		cleartextEndpoint := net.JoinHostPort(s.Address, fmt.Sprintf("%d", s.CleartextPort))
		s.startTCP(ctx, cleartextEndpoint)
		s.startUDP(ctx, cleartextEndpoint)
	}

	if s.EncryptedPort != 0 {
		encryptedEndpoint := net.JoinHostPort(s.Address, fmt.Sprintf("%d", s.EncryptedPort))
		s.startTLS(ctx, encryptedEndpoint)
		s.startDTLS(ctx, encryptedEndpoint)
	}
	go s.worker.ClearUnusedResource(ctx)
}

func (s *Server) startTCP(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveTCPAddr("tcp", addr)).(*net.TCPAddr)
	s.tcp = internal.Must2(net.ListenTCP("tcp", addr2)).(*net.TCPListener)
	lg.Infof("start TCP server at %s", s.tcp.Addr())

	go func() {
		for {
			conn, err := s.tcp.Accept()
			if err != nil {
				lg.Error(err)
				lg.Warning("stop TCP server")
				return
			}
			go s.worker.ServeStream(ctx, conn)
		}
	}()
}

func (s *Server) startTLS(ctx context.Context, addr string) {
	s.tls = internal.Must2(tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{s.Cert},
	})).(net.Listener)
	lg.Infof("start TLS server at %s", s.tls.Addr())

	go func() {
		for {
			conn, err := s.tls.Accept()
			if err != nil {
				lg.Error(err)
				lg.Warning("stop TLS server")
				return
			}
			go s.worker.ServeStream(ctx, conn)
		}
	}()
}

func (s *Server) startUDP(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveUDPAddr("udp", addr)).(*net.UDPAddr)
	s.udp = internal.Must2(net.ListenUDP("udp", addr2)).(*net.UDPConn)
	lg.Infof("start UDP server at %s", s.udp.LocalAddr())

	go func() {
		buf := make([]byte, 4096)
		for {
			nRead, rAddr, err := s.udp.ReadFrom(buf)
			if err != nil {
				lg.Error(err)
			}

			go s.worker.ServeDatagram(
				ctx,
				rAddr,
				buf[:nRead],
				func(b []byte) error {
					_, err := s.udp.WriteTo(b, rAddr)
					return err
				},
			)
		}
	}()
}

func (s *Server) startDTLS(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveUDPAddr("udp", addr)).(*net.UDPAddr)
	s.dtls = internal.Must2(dtls.Listen("udp", addr2, &dtls.Config{
		Certificates: []tls.Certificate{s.Cert},
	})).(net.Listener)
	lg.Infof("start DTLS server at %s", s.dtls.Addr())

	go func() {
		for {
			conn, err := s.dtls.Accept()
			if err != nil {
				lg.Error(err)
				lg.Warning("stop DTLS server")
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)

				for {
					nRead, err := conn.Read(buf)
					if err != nil {
						lg.Warningf("DTLS conn %s read error %s", conn.RemoteAddr(), err)
						return
					}
					go s.worker.ServeDatagram(
						ctx,
						conn.RemoteAddr(),
						buf[:nRead],
						func(b []byte) error {
							_, err := conn.Write(b)
							return err
						},
					)
				}
			}()
		}
	}()
}
