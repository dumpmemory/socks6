package socks6

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/common/nt"
	"github.com/studentmain/socks6/message"
)

func (s *ServerWorker) NoopHandler(
	ctx context.Context,
	cc SocksConn,
) {
	defer cc.Conn.Close()
	lg.Trace(cc.ConnId(), "noop")
	cc.WriteReplyCode(message.OperationReplySuccess)
}

func (s *ServerWorker) ConnectHandler(
	ctx context.Context,
	cc SocksConn,
) {
	defer cc.Conn.Close()
	clientAppliedOpt := message.StackOptionInfo{}
	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)

	lg.Trace(cc.ConnId(), "dial to", cc.Destination())

	rconn, remoteAppliedOpt, err := s.Outbound.Dial(ctx, remoteOpt, cc.Destination())
	code := getReplyCode(err)

	if code != message.OperationReplySuccess {
		lg.Warningf("%s dial to %s failed %+v", cc.ConnId(), cc.Destination(), err)
		cc.WriteReplyCode(code)
		return
	}
	defer rconn.Close()

	lg.Trace(cc.ConnId(), "remote conn established")
	if _, err := rconn.Write(cc.InitialData); err != nil {
		// it will fail again at relay()
		lg.Info(cc.ConnId(), "can't write initdata to remote connection")
	}

	appliedOpt := message.GetCombinedStackOptions(clientAppliedOpt, remoteAppliedOpt)
	options := message.NewOptionSet()
	options.AddMany(appliedOpt)
	// it will fail again at relay() too
	if err := cc.WriteReply(code, rconn.LocalAddr(), options); err != nil {
		lg.Warning(cc.ConnId(), "can't write reply", err)
	}

	relay(ctx, cc.Conn, rconn, 10*time.Minute)
	lg.Trace(cc.ConnId(), "relay end")
}

func (s *ServerWorker) BindHandler(
	ctx context.Context,
	cc SocksConn,
) {
	closeConn := common.NewCancellableDefer(func() {
		cc.Conn.Close()
	})

	defer closeConn.Defer()

	subStream := cc.MuxConn != nil

	if !subStream {
		// find backlogged listener
		bl, accept := s.backlogListener.Load(cc.Destination().String())
		if accept {
			lg.Info(cc.ConnId(), "trying accept backlogged connection at", bl.listener.Addr())
			// bl.handler is blocking, needn't cancel defer
			bl.handler(ctx, cc)
			return
		}
	}

	// not a backlogged accept

	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)
	iBacklog, backlogged := remoteOpt[message.StackOptionTCPBacklog]

	listener, remoteAppliedOpt, err := s.Outbound.Listen(ctx, remoteOpt, cc.Destination())
	lg.Info(cc.ConnId(), "bind at", listener.Addr())
	code := getReplyCode(err)
	if code != message.OperationReplySuccess {
		cc.WriteReplyCode(code)
		return
	}

	// add backlog option to notify client
	if backlogged {
		lg.Info(cc.ConnId(), "start backlogged bind at", listener.Addr())
		remoteAppliedOpt.Add(message.BaseStackOptionData{
			RemoteLeg: true,
			Level:     message.StackOptionLevelTCP,
			Code:      message.StackOptionCodeBacklog,
			Data: &message.BacklogOptionData{
				Backlog: iBacklog.(uint16),
			},
		})
	}

	appliedOpt := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	options := message.NewOptionSet()
	options.AddMany(appliedOpt)

	if err = cc.WriteReply(code, listener.Addr(), options); err != nil {
		lg.Error(cc.ConnId(), "can't write reply", err)
		return
	}
	// bind "handshake" done

	if backlogged {
		backlog := iBacklog.(uint16)
		if !subStream {

			// let backloglistener handle conn
			closeConn.Cancel()
			// backlog will only simulated on server
			// https://github.com/golang/go/issues/39000
			bl := newBacklogListener(listener, cc, backlog)

			blAddr := listener.Addr().String()
			s.backlogListener.Store(blAddr, bl)
			lg.Trace(cc.ConnId(), "start backlog listener worker")
			go bl.worker(ctx)
			return
		} else {

			bl := newBacklogMuxListener(ctx, listener, backlog)
			go func() {
				defer bl.Close()
				for {
					rconn, err2 := bl.Accept()
					if err2 != nil {
						return
					}
					go func(rconn net.Conn) {
						defer rconn.Close()

						cconn, err3 := cc.MuxConn.Dial()
						if err3 != nil {
							return
						}
						defer cconn.Close()

						rep := message.NewOperationReply()
						rep.Endpoint = message.ConvertAddr(rconn.RemoteAddr())
						cc.setStreamId(rep)
						_, err = cconn.Write(rep.Marshal())
						if err != nil {
							return
						}

						relay(ctx, cconn, rconn, time.Hour)
					}(rconn)
				}
			}()
		}
	}
	// non backlogged path
	defer listener.Close()
	// timeout or cancelled
	go func() {
		select {
		case <-time.After(60 * time.Second):
		case <-ctx.Done():
		}
		// can always close listener after 60s
		// in normal condition, listener accept exactly 1 conn, then close, another close call is unnecessary but safe
		// in error condition, of course close listener
		listener.Close()
	}()

	// accept a conn
	lg.Trace(cc.ConnId(), "waiting inbound connection")
	rconn, err := listener.Accept()
	listener.Close()
	code2 := getReplyCode(err)
	if code2 != message.OperationReplySuccess {
		cc.WriteReplyCode(code2)
		lg.Warning(cc.ConnId(), "can't accept inbound connection", err)
		return
	}
	lg.Info(cc.ConnId(), "inbound connection accepted")
	cc.WriteReplyAddr(code2, rconn.RemoteAddr())
	defer rconn.Close()

	relay(ctx, cc.Conn, rconn, 10*time.Minute)
	lg.Trace(cc.ConnId(), "relay end")
}

func (s *ServerWorker) UdpAssociateHandler(
	ctx context.Context,
	cc SocksConn,
) {
	closeConn := common.NewCancellableDefer(func() {
		cc.Conn.Close()
	})

	defer closeConn.Defer()

	destStr := cc.Destination().String()
	rid, reserved := s.reservedUdpAddr.Load(destStr)
	// already reserved
	if reserved {
		rua, ok := s.udpAssociation.Load(rid)
		if !ok {
			lg.Warning("reserve port exist after association delete")
		} else {
			// not same session, fail
			if !bytes.Equal(rua.cc.Session, cc.Session) {
				cc.WriteReplyCode(message.OperationReplyConnectionRefused)
				return
			}
		}
	}

	// reserve check pass
	remoteOpt := message.GetStackOptionInfo(cc.Request.Options, false)
	pc, remoteAppliedOpt, err := s.Outbound.ListenPacket(ctx, remoteOpt, cc.Destination())
	code := getReplyCode(err)
	if code != message.OperationReplySuccess {
		cc.WriteReplyCode(code)
		return
	}
	var reservedAddr net.Addr
	// reserve port
	if ippod, ok := remoteOpt[message.StackOptionUDPPortParity]; ok {
		appliedPpod := message.PortParityOptionData{
			Reserve: true,
			Parity:  message.StackPortParityOptionParityNo,
		}
		// calculate port to reserve
		ppod := ippod.(message.PortParityOptionData)
		if ppod.Reserve {
			s6a := message.ConvertAddr(pc.LocalAddr())
			if s6a.Port&1 == 0 {
				s6a.Port += 1
				appliedPpod.Parity = message.StackPortParityOptionParityEven
			} else {
				s6a.Port -= 1
				appliedPpod.Parity = message.StackPortParityOptionParityOdd
			}
			reservedAddr = s6a
		}
		// check and create reply option
		if !nt.UdpPortAvaliable(reservedAddr) {
			reservedAddr = nil
			appliedPpod.Reserve = false
		} else {
			remoteAppliedOpt.Add(message.BaseStackOptionData{
				RemoteLeg: true,
				Level:     message.StackOptionLevelUDP,
				Code:      message.StackOptionCodePortParity,
				Data:      &appliedPpod,
			})
		}
	}
	// check icmp option
	icmpOn := false
	if s.EnableICMP {
		if iicmp, ok := remoteOpt[message.StackOptionUDPUDPError]; ok {
			i := iicmp.(message.UDPErrorOptionData)
			if i.Availability {
				icmpOn = true
				remoteAppliedOpt.Add(message.BaseStackOptionData{
					RemoteLeg: true,
					Level:     message.StackOptionLevelUDP,
					Code:      message.StackOptionCodeUDPError,
					Data: &message.UDPErrorOptionData{
						Availability: true,
					},
				})
			}
		}
	}

	so := message.GetCombinedStackOptions(message.StackOptionInfo{}, remoteAppliedOpt)
	opset := message.NewOptionSet()
	opset.AddMany(so)
	cc.WriteReply(message.OperationReplySuccess, pc.LocalAddr(), opset)
	// start association
	assoc := newUdpAssociation(cc, pc, reservedAddr, s.AddressDependentFiltering, icmpOn)
	s.udpAssociation.Store(assoc.id, assoc)
	lg.Trace("start udp assoc", assoc.id)
	if reservedAddr != nil {
		s.reservedUdpAddr.Store(reservedAddr.String(), assoc.id)
	}
	closeConn.Cancel()

	go assoc.handleTcpUp(ctx)
	go assoc.handleUdpDown(ctx)
}
