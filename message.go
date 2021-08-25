package socks6

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"

	"net"
	"strconv"
)

type Endpoint struct {
	Port        uint16
	AddressType byte
	Address     []byte

	Net string
}

func NewEndpoint(addr string) Endpoint {
	r := Endpoint{}
	err := r.parseEndpoint(addr)
	if err != nil {
		return Endpoint{}
	}
	return r
}
func (e Endpoint) Network() string {
	return e.Net
}
func (e Endpoint) String() string {
	var s string
	switch e.AddressType {
	case AddressTypeDomainName:
		s = string(e.Address)
	case AddressTypeIPv4:
		ip := net.IP(e.Address[:4])
		s = ip.String()
	case AddressTypeIPv6:
		ip := net.IP(e.Address[:16])
		s = ip.String()
	}
	return net.JoinHostPort(s, strconv.FormatInt(int64(e.Port), 10))
}
func (e *Endpoint) parseEndpoint(s string) error {
	rhost, rports, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`[a-zA-Z]`)
	if strings.Contains(rhost, ":") {
		e.AddressType = AddressTypeIPv6
		e.Address = net.ParseIP(rhost).To16()
	} else if re.MatchString(rhost) {
		e.AddressType = AddressTypeDomainName
		e.Address = []byte(rhost)
	} else {
		e.AddressType = AddressTypeIPv4
		e.Address = net.ParseIP(rhost).To4()
	}
	rport, err := strconv.ParseUint(rports, 10, 16)
	e.Port = uint16(rport)
	if err != nil {
		return err
	}
	return nil
}

func (e *Endpoint) DeserializeAddress(b []byte) (int, error) {
	switch e.AddressType {
	case AddressTypeIPv4:
		if len(b) < 4 {
			return 0, ErrTooShort{ExpectedLen: 4}
		}
		e.Address = b[:4]
		return 4, nil
	case AddressTypeIPv6:
		if len(b) < 16 {
			return 0, ErrTooShort{ExpectedLen: 16}
		}
		e.Address = b[:16]
		return 16, nil
	case AddressTypeDomainName:
		if len(b) < 2 {
			return 0, ErrTooShort{ExpectedLen: 2}
		}
		al := b[0]
		if len(b) < int(al)+1 {
			return 0, ErrTooShort{ExpectedLen: int(al) + 1}
		}
		e.Address = bytes.TrimRight(b[1:al+1], "\u0000")
		return int(al) + 1, nil
	default:
		return 0, ErrAddressTypeNotSupport
	}
}
func (e Endpoint) SerializeAddress(b []byte) (int, error) {
	l := 0
	switch e.AddressType {
	case AddressTypeIPv4:
		l = 4
	case AddressTypeIPv6:
		l = 16
	case AddressTypeDomainName:
		l = len(e.Address) + 1
		// 4n+0=>(4n+0+3)/4*4=>(4n+3)/4*4=>4n
		// 4n+1=>(4n+1+3)/4*4=>(4n+4)/4*4=>4(n+1)
		// 4n+2=>(4n+2+3)/4*4=>(4n+4+1)/4*4=>4(n+1)
		// 4n+3=>(4n+3+3)/4*4=>(4n+4+2)/4*4=>4(n+1)
		expectedSize := PaddedLen(l, 4)
		if len(b) < expectedSize {
			return 0, ErrTooShort{ExpectedLen: expectedSize}
		}
	}
	if len(b) < l {
		return 0, ErrTooShort{ExpectedLen: l}
	}
	switch e.AddressType {
	case AddressTypeIPv4, AddressTypeIPv6:
		copy(b, e.Address)
		return l, nil
	case AddressTypeDomainName:
		p := (4 - l%4) % 4
		for i := 0; i < p; i++ {
			b[l+i] = 0
		}
		b[0] = byte(l + p - 1)
		copy(b[1:], e.Address)
		return l + p, nil
	default:
		return 0, ErrAddressTypeNotSupport
	}
}

type Message interface {
	Serialize(buf []byte) (int, error)
	Deserialize(buf []byte) (int, error)
}

type Request struct {
	Version     byte
	CommandCode byte
	Endpoint    Endpoint
	Options     OptionSet
}

func (r *Request) Serialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	buf[0] = 6
	buf[1] = r.CommandCode
	// optionlength, tbd
	binary.BigEndian.PutUint16(buf[4:], r.Endpoint.Port)
	buf[6] = 0
	buf[7] = r.Endpoint.AddressType

	hdrLen, err := r.Endpoint.SerializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8)
	}
	hdrLen += 8

	ops := r.Options.Marshal()
	totalLen := len(ops) + hdrLen
	if totalLen > len(buf) {
		return 0, ErrTooShort{ExpectedLen: totalLen}
	}
	copy(buf[hdrLen:], ops)
	binary.BigEndian.PutUint16(buf[2:], uint16(len(ops)))

	return totalLen, nil
}
func (r *Request) Deserialize(buf []byte) (int, error) {
	// special case to support fallback
	if len(buf) < 1 {
		return 0, ErrTooShort{ExpectedLen: 1}
	}
	if buf[0] != 6 {
		r.Version = buf[0]
		return 0, ErrVersion
	}
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	r.CommandCode = buf[1]
	opsLen := int(binary.BigEndian.Uint16(buf[2:]))
	r.Endpoint = Endpoint{}
	r.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	r.Endpoint.AddressType = buf[7]
	addrLen, err := r.Endpoint.DeserializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8+opsLen)
	}
	hdrLen := 8 + addrLen
	if opsLen+hdrLen > len(buf) {
		return 0, ErrTooShort{ExpectedLen: opsLen + hdrLen}
	}

	ops, l, err := parseOptions(buf[hdrLen:])
	if err != nil {
		return 0, addExpectedLen(err, hdrLen)
	}
	if l != opsLen {
		return 0, ErrFormat
	}
	r.Options = ops
	return hdrLen, nil
}

type AuthenticationReply struct {
	Type    byte
	Options []Option
}

func (a *AuthenticationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ErrTooShort{ExpectedLen: 4}
	}
	buf[0] = 6
	buf[1] = a.Type
	pOption := 4
	a.Options = []Option{}

	// todo serialize option
	for _, op := range a.Options {
		b := op.Marshal()
		if len(b)+pOption < len(buf) {
			return 0, ErrTooShort{ExpectedLen: len(b) + pOption}
		}
		copy(buf[pOption:], b)
		pOption += len(b)
	}
	binary.BigEndian.PutUint16(buf[2:], uint16(pOption-4))
	return pOption, nil
}
func (a *AuthenticationReply) Deserialize(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ErrTooShort{ExpectedLen: 4}
	}
	if buf[0] != 6 {
		return 0, ErrFormat
	}
	a.Type = buf[1]
	lOption := int(binary.BigEndian.Uint16(buf[2:]))
	if len(buf) < int(lOption)+4 {
		return 0, ErrTooShort{int(lOption) + 4}
	}
	pOption := 4
	a.Options = make([]Option, 0)
	for lOption >= 4 {
		b := buf[pOption:]
		op, err := ParseOption(b)
		if err != nil {
			// todo: malformed option length
			return 0, err
		}
		l := int(op.Length)
		pOption += l
		lOption -= l
		if lOption < 0 {
			return 0, ErrFormat
		}
		a.Options = append(a.Options, op)
	}
	return int(lOption) + 4, nil
}

type OperationReply struct {
	ReplyCode byte
	Endpoint  Endpoint
	Options   OptionSet
}

func (o *OperationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	buf[0] = 6
	buf[1] = o.ReplyCode
	binary.BigEndian.PutUint16(buf[4:], o.Endpoint.Port)
	buf[7] = o.Endpoint.AddressType

	addrLen, err := o.Endpoint.SerializeAddress(buf[8:])
	if err != nil {
		if ets, ok := err.(ErrTooShort); ok {
			return 0, ErrTooShort{ExpectedLen: ets.ExpectedLen + 8}
		}
		return 0, err
	}
	hdrLen := addrLen + 8

	ops := o.Options.Marshal()
	totalLen := hdrLen + len(ops)
	if len(buf) < totalLen {
		return 0, ErrTooShort{ExpectedLen: totalLen}
	}
	binary.BigEndian.PutUint16(buf[2:], uint16(len(ops)))
	return hdrLen, nil
}
func (o *OperationReply) Deserialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	if buf[0] != 6 {
		return 0, ErrFormat
	}
	o.ReplyCode = buf[1]
	opsLen := int(binary.BigEndian.Uint16(buf[2:]))
	o.Endpoint = Endpoint{}
	o.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	o.Endpoint.AddressType = buf[7]
	addrLen, err := o.Endpoint.DeserializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8+opsLen)
	}
	hdrLen := addrLen + 8
	totalLen := hdrLen + opsLen
	if len(buf) < totalLen {
		return 0, ErrTooShort{ExpectedLen: totalLen}
	}

	ops, l, err := parseOptions(buf[hdrLen:])
	if err != nil {
		return 0, addExpectedLen(err, hdrLen)
	}
	if l != opsLen {
		return 0, ErrFormat
	}
	o.Options = ops

	return totalLen, nil
}

type UDPHeader struct {
	Type          byte
	AssociationID uint64
	// dgram & icmp
	Endpoint Endpoint
	// icmp
	ErrorEndpoint Endpoint
	ErrorCode     byte
	// dgram
	Data []byte
}

func (u *UDPHeader) Serialize(buf []byte) (int, error) {
	switch u.Type {
	case UDPMessageAssociationInit, UDPMessageAssociationAck:
		if len(buf) < 12 {
			return 0, ErrTooShort{ExpectedLen: 12}
		}
		buf[0] = 6
		buf[1] = u.Type
		binary.BigEndian.PutUint16(buf[2:], 12)
		binary.BigEndian.PutUint64(buf[4:], u.AssociationID)
		return 12, nil
	case UDPMessageDatagram:
		if len(buf) < 18 {
			return 0, ErrTooShort{ExpectedLen: 18}
		}
		buf[0] = 6
		buf[1] = u.Type
		binary.BigEndian.PutUint64(buf[4:], u.AssociationID)
		buf[12] = u.Endpoint.AddressType
		binary.BigEndian.PutUint16(buf[14:], u.Endpoint.Port)
		l, err := u.Endpoint.SerializeAddress(buf[16:])
		if err != nil {
			return 0, addExpectedLen(err, 16+len(u.Data))
		}
		binary.BigEndian.PutUint16(buf[2:], uint16(16+l+len(u.Data)))
		copy(buf[16+l:], u.Data)
		return 16 + l + len(u.Data), nil
	case UDPMessageError:
		if len(buf) < 18 {
			return 0, ErrTooShort{ExpectedLen: 18}
		}
		buf[0] = 6
		buf[1] = u.Type
		binary.BigEndian.PutUint64(buf[4:], u.AssociationID)
		buf[12] = u.Endpoint.AddressType
		binary.BigEndian.PutUint16(buf[14:], u.Endpoint.Port)
		l, err := u.Endpoint.SerializeAddress(buf[16:])
		if err != nil {
			return 0, addExpectedLen(err, 16)
		}
		p := l + 16
		if len(buf) < p+6 {
			return 0, ErrTooShort{ExpectedLen: p + 6}
		}
		buf[p] = u.ErrorEndpoint.AddressType
		buf[p+1] = u.ErrorCode
		l, err = u.Endpoint.SerializeAddress(buf[p+4:])
		if err != nil {
			return 0, addExpectedLen(err, p+4)
		}
		binary.BigEndian.PutUint16(buf[2:], uint16(p+4+l))
		return p + 4 + l, nil
	}
	return 0, ErrEnumValue
}
func (u *UDPHeader) Deserialize(buf []byte) (int, error) {
	// todo socks5 fallback support?
	if len(buf) < 12 {
		return 0, ErrTooShort{ExpectedLen: 12}
	}
	lMsg := binary.BigEndian.Uint16(buf[2:])
	if len(buf) < int(lMsg) {
		return 0, ErrTooShort{ExpectedLen: int(lMsg)}
	}
	u.Type = buf[1]
	u.AssociationID = binary.BigEndian.Uint64(buf[4:])

	if u.Type == UDPMessageAssociationInit || u.Type == UDPMessageAssociationAck {
		return 12, nil
	}
	if len(buf) < 18 {
		return 0, ErrTooShort{ExpectedLen: 18}
	}
	u.Endpoint = Endpoint{
		AddressType: buf[12],
		Port:        binary.BigEndian.Uint16(buf[14:]),
	}
	lAddr, err := u.Endpoint.DeserializeAddress(buf[16:])
	if err != nil {
		return 0, addExpectedLen(err, 16)
	}
	lFull := binary.BigEndian.Uint16(buf[2:])
	if len(buf) < int(lFull) {
		return 0, ErrTooShort{ExpectedLen: int(lFull)}
	}
	if int(lFull) < 16+lAddr {
		return 0, ErrFormat
	}
	u.Data = buf[16+lAddr : lFull]

	if u.Type == UDPMessageDatagram {
		return int(lFull), nil
	}

	pIcmp := 16 + lAddr
	if len(buf) < pIcmp+6 {
		return 0, ErrTooShort{ExpectedLen: pIcmp + 6}
	}
	u.ErrorCode = buf[pIcmp+1]
	u.ErrorEndpoint = Endpoint{
		AddressType: buf[pIcmp],
	}
	lAddr2, err := u.ErrorEndpoint.DeserializeAddress(buf[pIcmp+4:])
	if err != nil {
		return 0, addExpectedLen(err, pIcmp+lAddr2+4)
	}
	return pIcmp + lAddr2 + 4, nil
}
