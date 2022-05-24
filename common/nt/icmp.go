package nt

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/studentmain/socks6/message"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmp utils

// protocol which has src and dst port (at "well-known" offset)
var protocolWithPort = map[int]bool{
	6:   true, // tcp
	17:  true, // udp
	33:  true, // dccp
	132: true, // sctp
}

func ParseSrcDstAddrFromIPHeader(header []byte, version int) (*message.SocksAddr, *message.SocksAddr, int, error) {
	switch version {
	case 4:
		hd, err := icmp.ParseIPv4Header(header)
		if err != nil {
			return nil, nil, 0, err
		}
		if _, ok := protocolWithPort[hd.Protocol]; !ok {
			return nil, nil, 0, errors.New("protocol not supported")
		}
		if len(header) < hd.Len+4 {
			return nil, nil, 0, errors.New("port field not exist")
		}
		data := header[hd.Len:]
		s := message.SocksAddr{
			AddressType: message.AddressTypeIPv4,
			Address:     hd.Src.To4(),
			Port:        binary.BigEndian.Uint16(data),
		}
		d := message.SocksAddr{
			AddressType: message.AddressTypeIPv4,
			Address:     hd.Dst.To4(),
			Port:        binary.BigEndian.Uint16(data[2:]),
		}
		return &s, &d, hd.Protocol, nil
	case 6:
		hd, err := ipv6.ParseHeader(header)
		if err != nil {
			return nil, nil, 0, err
		}
		if _, ok := protocolWithPort[hd.NextHeader]; !ok {
			return nil, nil, 0, errors.New("protocol not supported")
		}
		if len(header) < ipv6.HeaderLen+4 {
			return nil, nil, 0, errors.New("port field not exist")
		}
		data := header[ipv6.HeaderLen:]
		s := message.SocksAddr{
			AddressType: message.AddressTypeIPv6,
			Address:     hd.Src,
			Port:        binary.BigEndian.Uint16(data),
		}
		d := message.SocksAddr{
			AddressType: message.AddressTypeIPv6,
			Address:     hd.Dst,
			Port:        binary.BigEndian.Uint16(data[2:]),
		}
		return &s, &d, hd.NextHeader, nil
	default:
		return nil, nil, 0, errors.New("what ip version?")
	}
}

func convertICMPError(msg *icmp.Message, ip *net.IPAddr, ver int,
) (message.UDPErrorType, *message.SocksAddr, []byte) {
	var code message.UDPErrorType = 0
	var reporter *message.SocksAddr
	// map icmp message to socks6 addresses and code
	hdr := []byte{}

	switch ver {
	case 4:
		reporter = &message.SocksAddr{
			AddressType: message.AddressTypeIPv4,
			Address:     ip.IP.To4(),
		}

		switch msg.Type {
		case ipv4.ICMPTypeDestinationUnreachable:
			switch msg.Code {
			case 0:
				code = message.UDPErrorNetworkUnreachable
			case 1:
				code = message.UDPErrorHostUnreachable
			default:
				return 0, nil, nil
			}
			m2 := msg.Body.(*icmp.DstUnreach)
			hdr = m2.Data
		case ipv4.ICMPTypeTimeExceeded:
			switch msg.Code {
			case 0:
				code = message.UDPErrorTTLExpired
			default:
				return 0, nil, nil
			}
			m2 := msg.Body.(*icmp.TimeExceeded)
			hdr = m2.Data
		}
	case 6:
		reporter = &message.SocksAddr{
			AddressType: message.AddressTypeIPv6,
			Address:     ip.IP.To16(),
		}

		switch msg.Type {
		case ipv6.ICMPTypeDestinationUnreachable:
			switch msg.Code {
			case 0:
				code = message.UDPErrorNetworkUnreachable
			case 3:
				code = message.UDPErrorHostUnreachable
			default:
				return 0, nil, nil
			}
			m2 := msg.Body.(*icmp.DstUnreach)
			hdr = m2.Data
		case ipv6.ICMPTypeTimeExceeded:
			switch msg.Code {
			case 0:
				code = message.UDPErrorTTLExpired
			default:
				return 0, nil, nil
			}
			m2 := msg.Body.(*icmp.TimeExceeded)
			hdr = m2.Data
		case ipv6.ICMPTypePacketTooBig:
			code = message.UDPErrorDatagramTooBig
			m2 := msg.Body.(*icmp.TimeExceeded)
			hdr = m2.Data
		}
	}
	return code, reporter, hdr
}
