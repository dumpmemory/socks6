package socks6

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"golang.org/x/net/icmp"
)

// Server is a SOCKS 6 over TCP/TLS/UDP/DTLS server
// zero value is a cleartext only server with default server worker
type Server struct {
	Address       string
	CleartextPort uint16
	EncryptedPort uint16

	Cert *tls.Certificate

	Worker *ServerWorker

	// listeners

	tcp   net.Listener
	udp   net.PacketConn
	tls   net.Listener
	dtls  net.Listener
	icmp4 net.PacketConn
	icmp6 net.PacketConn

	listeners []canClose
}

type canClose interface {
	Close() error
}

func (s *Server) Start(ctx context.Context) {
	lg.Info("start SOCKS 6 listener")
	if s.Worker == nil {
		s.Worker = NewServerWorker()
	}
	s.listeners = []canClose{}

	if s.CleartextPort == 0 && s.EncryptedPort == 0 {
		s.CleartextPort = common.CleartextPort
		s.EncryptedPort = common.EncryptedPort
	}

	if s.CleartextPort != 0 {
		cleartextEndpoint := net.JoinHostPort(s.Address, fmt.Sprintf("%d", s.CleartextPort))
		s.startTCP(ctx, cleartextEndpoint)
		s.startUDP(ctx, cleartextEndpoint)
	}

	if s.EncryptedPort != 0 && s.Cert != nil {
		encryptedEndpoint := net.JoinHostPort(s.Address, fmt.Sprintf("%d", s.EncryptedPort))
		s.startTLS(ctx, encryptedEndpoint)
		s.startDTLS(ctx, encryptedEndpoint)
	}

	if s.Worker.EnableICMP {
		s.startICMP(ctx)
	}
	go s.Worker.ClearUnusedResource(ctx)
	go func() {
		<-ctx.Done()
		lg.Info("closing all listeners")
		for _, v := range s.listeners {
			err := v.Close()
			if err != nil {
				lg.Warning("error when close listener", err)
			}
		}
	}()
}

func (s *Server) startTCP(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveTCPAddr("tcp", addr))
	s.tcp = internal.Must2(net.ListenTCP("tcp", addr2))
	lg.Infof("start TCP server at %s", s.tcp.Addr())
	s.listeners = append(s.listeners, s.tcp)
	go func() {
		for {
			conn, err := s.tcp.Accept()
			if err != nil {
				lg.Error("stop TCP server", err)
				return
			}
			go s.Worker.ServeStream(ctx, conn)
		}
	}()
}

func (s *Server) startTLS(ctx context.Context, addr string) {
	s.tls = internal.Must2(tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{*s.Cert},
	}))
	lg.Infof("start TLS server at %s", s.tls.Addr())
	s.listeners = append(s.listeners, s.tls)

	go func() {
		for {
			conn, err := s.tls.Accept()
			if err != nil {
				lg.Error("stop TLS server", err)
				return
			}
			go s.Worker.ServeStream(ctx, conn)
		}
	}()
}

func (s *Server) startUDP(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveUDPAddr("udp", addr))
	s.udp = internal.Must2(net.ListenUDP("udp", addr2))
	lg.Infof("start UDP server at %s", s.udp.LocalAddr())
	s.listeners = append(s.listeners, s.udp)

	go func() {
		defer s.udp.Close()
		buf := internal.BytesPool4k.Rent()
		defer internal.BytesPool4k.Return(buf)

		for {
			nRead, rAddr, err := s.udp.ReadFrom(buf)
			if err != nil {
				lg.Error("stop UDP server", err)
				return
			}

			go s.Worker.ServeDatagram(
				ctx,
				Datagram{
					Addr: rAddr,
					Data: internal.Dup(buf[:nRead]),
					Downlink: func(b []byte) error {
						_, err := s.udp.WriteTo(b, rAddr)
						return err
					},
				},
			)
		}
	}()
}

func (s *Server) startDTLS(ctx context.Context, addr string) {
	addr2 := internal.Must2(net.ResolveUDPAddr("udp", addr))
	s.dtls = internal.Must2(dtls.Listen("udp", addr2, &dtls.Config{
		Certificates: []tls.Certificate{*s.Cert},
	}))
	lg.Infof("start DTLS server at %s", s.dtls.Addr())
	s.listeners = append(s.listeners, s.dtls)

	go func() {
		for {
			conn, err := s.dtls.Accept()
			if err != nil {
				lg.Error("stop DTLS server", err)
				return
			}
			go func() {
				defer conn.Close()

				buf := internal.BytesPool4k.Rent()
				defer internal.BytesPool4k.Return(buf)
				ds := DatagramSource{
					Addr: conn.RemoteAddr(),
					Data: new(chan []byte),
					Downlink: func(b []byte) error {
						_, err := conn.Write(b)
						return err
					},
				}
				go s.Worker.ServeDatagramSource(ctx, ds)
				for {
					nRead, err := conn.Read(buf)
					if err != nil {
						lg.Warningf("DTLS conn %s read error %s", conn.RemoteAddr(), err)
						return
					}
					*ds.Data <- internal.Dup(buf[:nRead])
				}
			}()
		}
	}()
}

func (s *Server) startICMP(ctx context.Context) {
	i4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		s.Worker.EnableICMP = false
		lg.Warning("can't listen ICMPv4 packet", err)
		return
	}
	i6, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		i4.Close()
		s.Worker.EnableICMP = false
		lg.Warning("can't listen ICMPv6 packet", err)
		return
	}
	s.icmp4 = i4
	s.icmp6 = i6
	s.listeners = append(s.listeners, s.icmp4)
	s.listeners = append(s.listeners, s.icmp6)

	fn := func(c net.PacketConn, ipv int) {
		b := internal.BytesPool4k.Rent()
		defer internal.BytesPool4k.Return(b)
		protov := 1
		switch ipv {
		case 4:
			protov = 1
		case 6:
			protov = 58
		}

		for {
			n, addr, err := c.ReadFrom(b)
			if err != nil {
				lg.Error(err)
				return
			}
			msg, err := icmp.ParseMessage(protov, b[:n])
			if err != nil {
				lg.Warning(err)
				continue
			}
			ip, ok := addr.(*net.IPAddr)
			if !ok {
				lg.Warning("ICMP ReadFrom returned a non IP address")
				continue
			}
			go s.Worker.ForwardICMP(ctx, msg, ip, ipv)
		}
	}
	go fn(s.icmp4, 4)
	go fn(s.icmp6, 6)
}
