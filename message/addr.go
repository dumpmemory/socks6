package message

import (
	"bytes"
	"io"
	"net"
	"strconv"

	"github.com/studentmain/socks6/internal"
	"github.com/studentmain/socks6/internal/lg"
	"golang.org/x/net/idna"
)

type AddressType byte

const (
	AddressTypeIPv4       AddressType = 1
	AddressTypeDomainName AddressType = 3
	AddressTypeIPv6       AddressType = 4
)

type Socks6Addr struct {
	AddressType AddressType
	Address     []byte
	Port        uint16
}

func ParseAddr(addr string) *Socks6Addr {
	r, err := NewAddr(addr)
	if err != nil {
		lg.Panic("can't parse address", addr, err)
	}
	return r
}

// AddrString create a stable string represtation for n
func AddrString(n net.Addr) string {
	s6a := ParseAddr(n.String())
	return s6a.String()
}

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
	if len(h) == 0 {
		atyp = AddressTypeIPv4
		addr = []byte{0, 0, 0, 0}
	} else if ip := net.ParseIP(h); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = AddressTypeIPv4
			addr = ip4
		} else {
			atyp = AddressTypeIPv6
			addr = ip
		}
	} else {
		asc, err := idna.ToASCII(h)
		if err != nil {
			return nil, err
		}
		if len(asc) > 255 {
			return nil, ErrFormat
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
func (a *Socks6Addr) Network() string {
	return "socks6"
}
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
func ParseAddressFrom(b io.Reader, atyp AddressType) (*Socks6Addr, error) {
	a := &Socks6Addr{}
	a.AddressType = atyp
	buf := internal.BytesPool256.Rent()
	defer internal.BytesPool256.Return(buf)
	if a.AddressType == AddressTypeDomainName {
		if _, err := io.ReadFull(b, buf[:1]); err != nil {
			return nil, err
		}
		l := buf[0]
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, err
		}
		a.Address = bytes.Trim(buf[:l], "\x00")
		return a, nil
	} else {
		l := 4
		if a.AddressType == AddressTypeIPv6 {
			l = 16
		} else if a.AddressType == AddressTypeIPv4 {
			l = 4
		} else {
			return nil, ErrAddressTypeNotSupport
		}
		if _, err := io.ReadFull(b, buf[:l]); err != nil {
			return nil, err
		}
		a.Address = internal.Dup(buf[:l])
		return a, nil
	}
}
func (s *Socks6Addr) AddrLen() int {
	switch s.AddressType {
	case AddressTypeIPv4:
		return 4
	case AddressTypeIPv6:
		return 16
	case AddressTypeDomainName:
		return len(s.Address) + 1
	default:
		lg.Error("address type not set")
		return 0
	}
}
