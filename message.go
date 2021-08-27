package socks6

import (
	"bytes"
	"encoding/binary"
)

type Message interface {
	Serialize(buf []byte) (int, error)
	Deserialize(buf []byte) (int, error)
}

type Request struct {
	Version     byte
	CommandCode byte
	Endpoint    Addr
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
	buf[7] = byte(r.Endpoint.AddressType)
	addr := r.Endpoint.MarshalAddress()
	hdrLen := len(addr) + 8
	if len(buf) < hdrLen {
		return 0, ErrTooShort{ExpectedLen: hdrLen}
	}
	copy(buf[8:], addr)

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
	r.Endpoint = Addr{}
	r.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	addrLen, err := r.Endpoint.ParseAddress(AddressType(buf[7]), buf[8:])
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
	return hdrLen + opsLen, nil
}

type AuthenticationReply struct {
	Type    byte
	Options OptionSet
}

func (a *AuthenticationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ErrTooShort{ExpectedLen: 4}
	}
	buf[0] = 6
	buf[1] = a.Type
	hdrLen := 4

	ops := a.Options.Marshal()
	totalLen := len(ops) + hdrLen
	if totalLen > len(buf) {
		return 0, ErrTooShort{ExpectedLen: totalLen}
	}
	copy(buf[4:], ops)
	binary.BigEndian.PutUint16(buf[2:], uint16(len(ops)))
	return totalLen, nil
}
func (a *AuthenticationReply) Deserialize(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ErrTooShort{ExpectedLen: 4}
	}
	if buf[0] != 6 {
		return 0, ErrFormat
	}
	a.Type = buf[1]
	opsLen := int(binary.BigEndian.Uint16(buf[2:]))
	if len(buf) < int(opsLen)+4 {
		return 0, ErrTooShort{opsLen + 4}
	}
	hdrLen := 4
	ops, l, err := parseOptions(buf[hdrLen:])
	if err != nil {
		return 0, addExpectedLen(err, hdrLen)
	}
	if l != opsLen {
		return 0, ErrFormat
	}
	a.Options = ops

	return hdrLen + opsLen, nil
}

type OperationReply struct {
	ReplyCode byte
	Endpoint  Addr
	Options   OptionSet
}

func (o *OperationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	buf[0] = 6
	buf[1] = o.ReplyCode
	binary.BigEndian.PutUint16(buf[4:], o.Endpoint.Port)
	buf[7] = byte(o.Endpoint.AddressType)
	addr := o.Endpoint.MarshalAddress()
	hdrLen := len(addr) + 8
	if len(buf) < hdrLen {
		return 0, ErrTooShort{ExpectedLen: hdrLen}
	}
	copy(buf[8:], addr)

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
	o.Endpoint = Addr{}
	o.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	addrLen, err := o.Endpoint.ParseAddress(AddressType(buf[7]), buf[8:])
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
	Endpoint Addr
	// icmp
	ErrorEndpoint Addr
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
		addr := u.Endpoint.MarshalAddress()
		totalLen := 16 + len(addr) + len(u.Data)
		if len(buf) < totalLen {
			return 0, ErrTooShort{ExpectedLen: totalLen}
		}
		b := bytes.NewBuffer(buf)
		b.WriteByte(6)
		b.WriteByte(u.Type)
		binary.Write(b, binary.BigEndian, totalLen)
		binary.Write(b, binary.BigEndian, u.AssociationID)

		b.WriteByte(byte(u.Endpoint.AddressType))
		b.WriteByte(0)
		binary.Write(b, binary.BigEndian, len(addr))
		b.Write(addr)

		b.Write(u.Data)

		return totalLen, nil
	case UDPMessageError:
		addr := u.Endpoint.MarshalAddress()
		eaddr := u.ErrorEndpoint.MarshalAddress()
		totalLen := 20 + len(addr) + len(eaddr)

		if len(buf) < totalLen {
			return 0, ErrTooShort{ExpectedLen: totalLen}
		}
		b := bytes.NewBuffer(buf)

		b.WriteByte(6)
		b.WriteByte(u.Type)
		binary.Write(b, binary.BigEndian, totalLen)

		binary.Write(b, binary.BigEndian, u.AssociationID)

		b.WriteByte(byte(u.Endpoint.AddressType))
		b.WriteByte(0)
		binary.Write(b, binary.BigEndian, u.Endpoint.Port)

		b.Write(addr)

		b.WriteByte(byte(u.ErrorEndpoint.AddressType))
		b.WriteByte(u.ErrorCode)
		b.WriteByte(0)
		b.WriteByte(0)

		b.Write(eaddr)

		return totalLen, nil
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
	u.Endpoint = Addr{
		Port: binary.BigEndian.Uint16(buf[14:]),
	}
	lAddr, err := u.Endpoint.ParseAddress(AddressType(buf[12]), buf[16:])
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
	u.ErrorEndpoint = Addr{}
	lAddr2, err := u.ErrorEndpoint.ParseAddress(AddressType(buf[pIcmp]), buf[pIcmp+4:])
	if err != nil {
		return 0, addExpectedLen(err, pIcmp+lAddr2+4)
	}
	return pIcmp + lAddr2 + 4, nil
}
