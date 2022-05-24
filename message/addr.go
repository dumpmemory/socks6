package message

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/studentmain/socks6/common/arrayx"
	"github.com/studentmain/socks6/common/lg"
	"golang.org/x/net/idna"
)

type AddressType byte

const (
	AddressTypeIPv4       AddressType = 1
	AddressTypeDomainName AddressType = 3
	AddressTypeIPv6       AddressType = 4
)

// SocksAddr is address and port used in SOCKS6 protocol
type SocksAddr struct {
	// address' type
	AddressType AddressType
	// actual address,
	// if AddressType is IPv4/IPv6, contains IP address byte.
	// If AddressType is DomainName, contains domain name in punycode encoded format without leading length byte and padding.
	Address []byte
	// port used by transport layer protocol
	Port uint16
}

var _ net.Addr = &SocksAddr{}

// AddrIPv4Zero is 0.0.0.0:0 in SocksAddr format
var AddrIPv4Zero *SocksAddr = &SocksAddr{
	AddressType: AddressTypeIPv4,
	Address:     []byte{0, 0, 0, 0},
	Port:        0,
}

// AddrIPv6Zero is [::]:0 in SocksAddr format
var AddrIPv6Zero *SocksAddr = &SocksAddr{
	AddressType: AddressTypeIPv6,
	Address: []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0},
	Port: 0,
}

// DefaultAddr is 0.0.0.0:0 in SocksAddr format
var DefaultAddr *SocksAddr = AddrIPv4Zero

// ParseAddr parse address string to SocksAddr
// panic when error
func ParseAddr(addr string) *SocksAddr {
	r, err := NewAddr(addr)
	if err != nil {
		lg.Panic("can't parse address", addr, err)
	}
	return r
}

// ConvertAddr try to convert net.Addr to SocksAddr
func ConvertAddr(addr net.Addr) *SocksAddr {
	var ip net.IP
	var port int
	if addr == nil {
		return DefaultAddr
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
		port = a.Port
	case *net.UDPAddr:
		ip = a.IP
		port = a.Port
	case *SocksAddr:
		return a
	default:
		return ParseAddr(addr.String())
	}
	// only TCP/UDPAddr can reach here
	// convert IP address to avoid unnecessary use of IPv6
	af := AddressTypeIPv6
	if ip4 := ip.To4(); ip4 != nil {
		af = AddressTypeIPv4
		ip = ip4
	}
	return &SocksAddr{
		AddressType: af,
		Address:     ip,
		Port:        uint16(port),
	}
}

// NewAddr parse address string to SocksAddr
func NewAddr(address string) (*SocksAddr, error) {
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return nil, err
	}
	var atyp AddressType
	var addr []byte
	// no host part, assume ipv4
	if len(h) == 0 {
		atyp = AddressTypeIPv4
		addr = []byte{0, 0, 0, 0}
	} else if ip := net.ParseIP(h); ip != nil {
		// is ip address
		if ip4 := ip.To4(); ip4 != nil {
			// is ipv4, use 4 byte IP
			atyp = AddressTypeIPv4
			addr = ip4
		} else {
			// ipv6
			atyp = AddressTypeIPv6
			addr = ip
		}
	} else {
		// is domain name
		// convert to punycode encoded format
		asc, err := idna.ToASCII(h)
		if err != nil {
			return nil, err
		}
		if len(asc) > 255 {
			return nil, ErrFormat.WithVerbose("domain name shouldn't longer than 255")
		}
		atyp = AddressTypeDomainName
		addr = arrayx.Dup([]byte(asc))
	}
	return &SocksAddr{
		AddressType: atyp,
		Address:     addr,
		Port:        uint16(port),
	}, nil
}

// Network implements net.Addr, always return "socks"
func (a *SocksAddr) Network() string {
	return "socks"
}

// String implements net.Addr
func (a *SocksAddr) String() string {
	var h string
	switch a.AddressType {
	case AddressTypeIPv4, AddressTypeIPv6:
		h = net.IP(a.Address).String()
	case AddressTypeDomainName:
		h = string(a.Address)
	}
	return net.JoinHostPort(h, strconv.FormatInt(int64(a.Port), 10))
}

// Marshal6 serialize to socks 6 wireformat
func (a *SocksAddr) Marshal6(pad byte) []byte {
	lg.Debugf("serialize socks 6 address %+v, padding %d", a, pad)
	b := &bytes.Buffer{}
	binary.Write(b, binary.BigEndian, a.Port)
	b.WriteByte(pad)
	b.WriteByte(byte(a.AddressType))

	npad := 0
	if a.AddressType == AddressTypeDomainName {
		l := 1 + len(a.Address)
		total := arrayx.PaddedLen(l, 4)
		lg.Debugf("serialize socks 6 address domain name, padding %d to %d", total, l)
		if total > 255 {
			lg.Panic("address too long")
		}
		b.WriteByte(byte(total))
		npad = total - l
	}
	b.Write(a.Address)
	if npad > 0 {
		b.Write(make([]byte, npad))
	}

	ret := b.Bytes()
	lg.Debugf("serialize socks 6 address %+v to %+v", a, ret)
	return ret
}

// ParseSocksAddr6FromWithLimit parse socks 6 address with border check
func ParseSocksAddr6FromWithLimit(b io.Reader, limit int) (addr *SocksAddr, pad byte, nConsume int, err error) {
	lg.Debugf("read socks 6 address withing %d byte", limit)
	if limit <= 4 {
		return nil, 0, 0, ErrBufferSize
	}
	addr = &SocksAddr{}
	buf := make([]byte, 256)
	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, 0, 0, err
	}
	lg.Debug("read socks 6 address port padding atyp", buf[:4])
	addr.Port = binary.BigEndian.Uint16(buf)
	padding := buf[2]
	addr.AddressType = AddressType(buf[3])

	if addr.AddressType == AddressTypeDomainName {
		lg.Debug("read socks 6 address domain name")
		// domain name
		// read length
		if limit <= 5 {
			return nil, 0, 0, ErrBufferSize
		}
		if _, err := io.ReadFull(b, buf[:1]); err != nil {
			return nil, 0, 0, err
		}
		lg.Debug("read socks 6 address domain name length", buf[0])
		l := buf[0]
		if int(l)+5 >= limit {
			return nil, 0, 0, ErrBufferSize
		}
		// read addr
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, 0, 0, err
		}
		lg.Debug("read socks 6 address domain raw", buf[:l])
		// remove padding
		addr.Address = bytes.Trim(buf[:l], "\x00")
		lg.Debug("read socks 6 address domain trimmed", addr.Address)
		lg.Debugf("read socks 6 address %+v, padding %d, used %d", addr, padding, int(l)+5)
		return addr, padding, int(l) + 5, nil
	} else {
		lg.Debug("read socks 6 address ip")
		// ip
		l := 4
		// determine reading length
		switch addr.AddressType {
		case AddressTypeIPv6:
			l = 16
		case AddressTypeIPv4:
			l = 4
		default:
			// unknown address type
			return nil, 0, 0, ErrAddressTypeNotSupport
		}
		if limit < l+4 {
			return nil, 0, 0, ErrBufferSize
		}
		// read addr
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, 0, 0, err
		}
		addr.Address = arrayx.Dup(buf[:l])
		lg.Debug("read socks 6 address ip", addr.Address)
		lg.Debugf("read socks 6 address %+v, padding %d, used %d", addr, padding, int(l)+4)
		return addr, padding, int(l) + 4, nil
	}
}

// ParseSocksAddr6FromWithLimit parse socks 6 address with border set to 260 byte
func ParseSocksAddr6From(b io.Reader) (addr *SocksAddr, pad byte, nConsume int, err error) {
	return ParseSocksAddr6FromWithLimit(b, 260)
}

func (a *SocksAddr) Marshal5() []byte {
	lg.Debugf("serialize socks 5 address %+v", a)

	b := &bytes.Buffer{}
	b.WriteByte(byte(a.AddressType))

	if a.AddressType == AddressTypeDomainName {
		l := 1 + len(a.Address)
		if l > 255 {
			lg.Panic("address too long")
		}
		b.WriteByte(byte(l))
	}
	b.Write(a.Address)
	binary.Write(b, binary.BigEndian, a.Port)

	ret := b.Bytes()
	lg.Debugf("serialize socks 5 address %+v to %+v", a, ret)
	return ret
}

func ParseSocksAddr5From(b io.Reader) (*SocksAddr, error) {
	lg.Debug("read socks 5 address")

	buf := make([]byte, 256)
	a := &SocksAddr{}
	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	lg.Debug("read socks 5 address atyp", buf[0])

	a.AddressType = AddressType(buf[0])
	l := byte(4)

	if a.AddressType == AddressTypeDomainName {
		if _, err := io.ReadFull(b, buf[:1]); err != nil {
			return nil, err
		}
		l = buf[0]

		lg.Debug("read socks 5 address domain name length", l)
	} else {
		switch a.AddressType {
		case AddressTypeIPv6:
			l = 16
		case AddressTypeIPv4:
			l = 4
		default:
			return nil, ErrAddressTypeNotSupport
		}
	}
	if _, err := io.ReadFull(b, buf[:l+2]); err != nil {
		return nil, err
	}
	lg.Debug("read socks 5 address host port", buf[:l+2])
	a.Address = arrayx.Dup(buf[:l])
	a.Port = binary.BigEndian.Uint16(buf[l:])
	lg.Debug("read socks 5 address", a)
	return a, nil
}
