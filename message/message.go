package message

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/studentmain/socks6/internal"
)

type CommandCode byte

const (
	CommandNoop CommandCode = iota
	CommandConnect
	CommandBind
	CommandUdpAssociate
)

type Request struct {
	CommandCode CommandCode
	Endpoint    *Socks6Addr
	Options     *OptionSet
}

func ParseRequestFrom(b io.Reader) (*Request, error) {
	r := &Request{}
	buf := make([]byte, math.MaxUint16)

	// ver cc opLen2 port2 0 aTyp
	if _, err := io.ReadFull(b, buf[:8]); err != nil {
		return nil, err
	}
	if buf[0] != 6 {
		return r, ErrVersion{Version: int(buf[0]), ConsumedBytes: buf[:8]}
	}
	r.CommandCode = CommandCode(buf[1])
	optLen := binary.BigEndian.Uint16(buf[2:])

	aTyp := AddressType(buf[7])
	addr, err := ParseAddressFrom(b, aTyp)
	if err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(buf[4:])
	r.Endpoint = addr

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	return r, nil
}
func (r *Request) Marshal() (buf []byte) {
	ops := r.Options.Marshal()
	addr := r.Endpoint.MarshalAddress()

	b := bytes.NewBuffer(buf)

	b.WriteByte(6)
	b.WriteByte(byte(r.CommandCode))
	binary.Write(b, binary.BigEndian, uint16(len(ops)))

	binary.Write(b, binary.BigEndian, r.Endpoint.Port)
	b.WriteByte(0)
	b.WriteByte(byte(r.Endpoint.AddressType))

	b.Write(addr)

	b.Write(ops)
	return b.Bytes()
}

type AuthenticationReplyType byte

const (
	AuthenticationReplySuccess AuthenticationReplyType = 0
	AuthenticationReplyFail    AuthenticationReplyType = 1
)

type AuthenticationReply struct {
	Type    AuthenticationReplyType
	Options *OptionSet
}

func (a *AuthenticationReply) Marshal() []byte {
	ops := a.Options.Marshal()
	b := bytes.Buffer{}

	b.WriteByte(6)
	b.WriteByte(byte(a.Type))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	b.Write(ops)
	return b.Bytes()
}
func ParseAuthenticationReplyFrom(b io.Reader) (*AuthenticationReply, error) {
	a := &AuthenticationReply{}
	buf := make([]byte, math.MaxUint16)
	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}
	if buf[0] != 6 {
		return nil, ErrProtocolPolice
	}
	a.Type = AuthenticationReplyType(buf[1])
	opsLen := int(binary.BigEndian.Uint16(buf[2:]))
	ops, err := ParseOptionSetFrom(b, opsLen)
	if err != nil {
		return nil, err
	}
	a.Options = ops
	return a, nil
}

type ReplyCode byte

const (
	OperationReplySuccess ReplyCode = iota
	OperationReplyServerFailure
	OperationReplyNotAllowedByRule
	OperationReplyNetworkUnreachable
	OperationReplyHostUnreachable
	OperationReplyConnectionRefused
	OperationReplyTTLExpired
	OperationReplyCommandNotSupported
	OperationReplyAddressNotSupported
	OperationReplyTimeout
)

type OperationReply struct {
	ReplyCode ReplyCode
	Endpoint  *Socks6Addr
	Options   *OptionSet
}

func (o *OperationReply) Marshal() []byte {
	ops := o.Options.Marshal()
	addr := o.Endpoint.MarshalAddress()

	b := bytes.Buffer{}

	b.WriteByte(6)
	b.WriteByte(byte(o.ReplyCode))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	binary.Write(&b, binary.BigEndian, o.Endpoint.Port)
	b.WriteByte(0)
	b.WriteByte(byte(o.Endpoint.AddressType))

	b.Write(addr)

	b.Write(ops)
	return b.Bytes()
}
func ParseOperationReplyFrom(b io.Reader) (*OperationReply, error) {
	r := &OperationReply{}
	buf := make([]byte, math.MaxUint16)

	// ver cc opLen2 port2 0 aTyp
	if _, err := io.ReadFull(b, buf[:8]); err != nil {
		return nil, err
	}
	if buf[0] != 6 {
		return r, ErrProtocolPolice
	}
	r.ReplyCode = ReplyCode(buf[1])
	optLen := binary.BigEndian.Uint16(buf[2:])

	aTyp := AddressType(buf[7])
	addr, err := ParseAddressFrom(b, aTyp)
	if err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(buf[4:])
	r.Endpoint = addr

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	return r, nil
}

const (
	_ byte = iota
	UDPMessageAssociationInit
	UDPMessageAssociationAck
	UDPMessageDatagram
	UDPMessageError
)

type UDPHeader struct {
	Type          byte
	AssociationID uint64
	// dgram & icmp
	Endpoint *Socks6Addr
	// icmp
	ErrorEndpoint *Socks6Addr
	ErrorCode     byte
	// dgram
	Data []byte
}

func (u *UDPHeader) Marshal() []byte {
	b := bytes.Buffer{}

	switch u.Type {
	case UDPMessageAssociationInit, UDPMessageAssociationAck:
		b.WriteByte(6)
		b.WriteByte(u.Type)
		binary.Write(&b, binary.BigEndian, uint16(12))
		binary.Write(&b, binary.BigEndian, u.AssociationID)
	case UDPMessageDatagram:
		addr := u.Endpoint.MarshalAddress()
		totalLen := 16 + len(addr) + len(u.Data)
		b.WriteByte(6)
		b.WriteByte(u.Type)
		binary.Write(&b, binary.BigEndian, uint16(totalLen))
		binary.Write(&b, binary.BigEndian, u.AssociationID)

		b.WriteByte(byte(u.Endpoint.AddressType))
		b.WriteByte(0)
		binary.Write(&b, binary.BigEndian, uint16(len(addr)))
		b.Write(addr)

		b.Write(u.Data)
	case UDPMessageError:
		addr := u.Endpoint.MarshalAddress()
		eaddr := u.ErrorEndpoint.MarshalAddress()
		totalLen := 20 + len(addr) + len(eaddr)

		b.WriteByte(6)
		b.WriteByte(u.Type)
		binary.Write(&b, binary.BigEndian, uint16(totalLen))

		binary.Write(&b, binary.BigEndian, u.AssociationID)

		b.WriteByte(byte(u.Endpoint.AddressType))
		b.WriteByte(0)
		binary.Write(&b, binary.BigEndian, u.Endpoint.Port)

		b.Write(addr)

		b.WriteByte(byte(u.ErrorEndpoint.AddressType))
		b.WriteByte(u.ErrorCode)
		b.WriteByte(0)
		b.WriteByte(0)

		b.Write(eaddr)
	}
	return b.Bytes()
}

func ParseUDPHeaderFrom(b io.Reader) (*UDPHeader, error) {
	u := &UDPHeader{}
	buf := make([]byte, math.MaxUint16)
	if _, err := io.ReadFull(b, buf[:8]); err != nil {
		return nil, err
	}
	if buf[0] != 6 {
		return nil, ErrVersion{Version: int(buf[0])}
	}

	totalLen := binary.BigEndian.Uint16(buf[2:])

	u.Type = buf[1]
	u.AssociationID = binary.BigEndian.Uint64(buf[4:])

	if u.Type == UDPMessageAssociationInit || u.Type == UDPMessageAssociationAck {
		return u, nil
	}

	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}

	// todo possible desync: msgLength = 20, atyp = 3, addr[0] = 100
	addr, err := ParseAddressFrom(b, AddressType(buf[0]))
	if err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(buf[2:])
	u.Endpoint = addr
	remainLen := totalLen - uint16(addr.AddrLen())
	if u.Type == UDPMessageDatagram {
		if _, err := io.ReadFull(b, buf[:remainLen]); err != nil {
			return nil, err
		}
		u.Data = internal.Dup(buf[:remainLen])
		return u, nil
	}

	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}

	u.ErrorCode = buf[1]

	// todo possible desync2
	eaddr, err := ParseAddressFrom(b, AddressType(buf[0]))
	if err != nil {
		return nil, err
	}
	u.ErrorEndpoint = eaddr

	return u, nil
}
