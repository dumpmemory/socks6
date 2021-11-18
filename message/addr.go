package message

import (
	"bytes"
	"io"
	"net"
	"strconv"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
	"golang.org/x/net/idna"
)

type AddressType byte

const (
	AddressTypeIPv4       AddressType = 1
	AddressTypeDomainName AddressType = 3
	AddressTypeIPv6       AddressType = 4
)

// Socks6Addr is address and port used in SOCKS6 protocol
type Socks6Addr struct {
	// address' type
	AddressType AddressType
	// actual address,
	// if AddressType is IPv4/IPv6, contains IP address byte.
	// If AddressType is DomainName, contains domain name in punycode encoded format without leading length byte and padding.
	Address []byte
	// port used by transport layer protocol
	Port uint16
}

// AddrIPv4Zero is 0.0.0.0:0 in Socks6Addr format
var AddrIPv4Zero *Socks6Addr = &Socks6Addr{
	AddressType: AddressTypeIPv4,
	Address:     []byte{0, 0, 0, 0},
	Port:        0,
}

// AddrIPv6Zero is [::]:0 in Socks6Addr format
var AddrIPv6Zero *Socks6Addr = &Socks6Addr{
	AddressType: AddressTypeIPv6,
	Address: []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0},
	Port: 0,
}

// DefaultAddr is 0.0.0.0:0 in Socks6Addr format
var DefaultAddr *Socks6Addr = AddrIPv4Zero

// ParseAddr parse address string to Socks6Addr
// panic when error
func ParseAddr(addr string) *Socks6Addr {
	r, err := NewAddr(addr)
	if err != nil {
		lg.Panic("can't parse address", addr, err)
	}
	return r
}

// ConvertAddr try to convert net.Addr to Socks6Addr
func ConvertAddr(addr net.Addr) *Socks6Addr {
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
	case *Socks6Addr:
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
	return &Socks6Addr{
		AddressType: af,
		Address:     ip,
		Port:        uint16(port),
	}
}

// AddrString create a stable string represtation for input address for hashing purpose
// todo needn't
func AddrString(n net.Addr) string {
	s6a := ConvertAddr(n)
	return s6a.String()
}

// NewAddr parse address string to Socks6Addr
func NewAddr(address string) (*Socks6Addr, error) {
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
		addr = internal.Dup([]byte(asc))
	}
	return &Socks6Addr{
		AddressType: atyp,
		Address:     addr,
		Port:        uint16(port),
	}, nil
}

// Network implements net.Conn, always return "socks6"
func (a *Socks6Addr) Network() string {
	return "socks6"
}

// String implements net.Conn
func (a *Socks6Addr) String() string {
	var h string
	switch a.AddressType {
	case AddressTypeIPv4, AddressTypeIPv6:
		h = net.IP(a.Address).String()
	case AddressTypeDomainName:
		h = string(a.Address)
	}
	return net.JoinHostPort(h, strconv.FormatInt(int64(a.Port), 10))
}

// MarshalAddress get host address' (without port) wireformat representation
func (a *Socks6Addr) MarshalAddress() []byte {
	if a.AddressType == AddressTypeDomainName {
		r := append([]byte{byte(len(a.Address))}, a.Address...)
		total := internal.PaddedLen(len(r), 4)
		lPad := total - len(r)
		r = append(r, make([]byte, lPad)...)
		r[0] = byte(total) - 1
		return r
	}
	l := 16
	if a.AddressType == AddressTypeIPv4 {
		l = 4
	}
	return internal.Dup(a.Address[:l])
}

// ParseAddressFrom read address of given type from reader
func ParseAddressFrom(b io.Reader, atyp AddressType) (*Socks6Addr, error) {
	a := &Socks6Addr{}
	a.AddressType = atyp
	buf := make([]byte, 256)

	if a.AddressType == AddressTypeDomainName {
		// domain name
		// read length
		if _, err := io.ReadFull(b, buf[:1]); err != nil {
			return nil, err
		}
		l := buf[0]
		// read addr
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, err
		}
		// remove padding
		a.Address = bytes.Trim(buf[:l], "\x00")
		return a, nil
	} else {
		// ip
		l := 4
		// determine reading length
		switch a.AddressType {
		case AddressTypeIPv6:
			l = 16
		case AddressTypeIPv4:
			l = 4
		default:
			// unknown address type
			return nil, ErrAddressTypeNotSupport
		}
		// read addr
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, err
		}
		a.Address = internal.Dup(buf[:l])
		return a, nil
	}
}

// AddrLen return host address' wireformat length without padding
func (s *Socks6Addr) AddrLen() int {
	switch s.AddressType {
	case AddressTypeIPv4:
		return 4
	case AddressTypeIPv6:
		return 16
	case AddressTypeDomainName:
		return len(s.Address) + 1
	default:
		lg.Panic("address type not set")
		return 0
	}
}
