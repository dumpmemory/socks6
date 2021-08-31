package message

import (
	"bytes"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/studentmain/socks6/internal"
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

	Net string
}

func NewAddrP(addr string) *Socks6Addr {
	r, err := NewAddr(addr)
	if err != nil {
		log.Panic(err)
	}
	return r
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
	if ip := net.ParseIP(h); ip != nil {
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
	return a.Net
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
func (a *Socks6Addr) ParseAddress(atyp AddressType, addr []byte) (int, error) {
	a.AddressType = atyp
	expLen := 0
	switch a.AddressType {
	case AddressTypeIPv4:
		expLen = 4
	case AddressTypeIPv6:
		expLen = 16
	case AddressTypeDomainName:
		if len(addr) < 2 {
			expLen = 2
		} else {
			expLen = int(addr[0]) + 1
		}
	default:
		return 0, ErrAddressTypeNotSupport
	}
	if len(addr) < expLen {
		return 0, ErrTooShort{ExpectedLen: expLen}
	}

	switch a.AddressType {
	case AddressTypeIPv4:
		a.Address = internal.Dup(addr[:4])
	case AddressTypeIPv6:
		a.Address = internal.Dup(addr[:16])
	case AddressTypeDomainName:
		a.Address = bytes.Trim(addr[1:expLen], "\x00")
	}
	return expLen, nil
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
	buf := make([]byte, 256)
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
		log.Panic("address type not set")
		return 0
	}
}
