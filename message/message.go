// message contains SOCKS 6 wireformat parser and serializer
package message

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/studentmain/socks6/internal"
)

// CommandCode is SOCKS 6 request command code
type CommandCode byte

const (
	CommandNoop CommandCode = iota
	CommandConnect
	CommandBind
	CommandUdpAssociate
)

type Request struct {
	CommandCode CommandCode
	Endpoint    *SocksAddr
	Options     *OptionSet
}

func NewRequest() *Request {
	return &Request{
		Endpoint: &SocksAddr{
			AddressType: AddressTypeIPv4,
			Address:     []byte{0, 0, 0, 0},
		},
		Options: NewOptionSet(),
	}
}
func ParseRequestFrom(b io.Reader) (*Request, error) {
	r := &Request{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)

	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	if buf[0] != protocolVersion {
		return r, ErrVersionMismatch{Version: int(buf[0]), ConsumedBytes: buf[:1]}
	}
	// ver cc opLen2
	if _, err := io.ReadFull(b, buf[1:4]); err != nil {
		return nil, err
	}

	r.CommandCode = CommandCode(buf[1])
	optLen := binary.BigEndian.Uint16(buf[2:])

	addr, _, _, err := ParseSocksAddr6From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	return r, nil
}
func (r *Request) Marshal() (buf []byte) {
	ops := []byte{}
	if r.Options != nil {
		ops = r.Options.Marshal()
	}
	b := bytes.NewBuffer(buf)

	b.WriteByte(protocolVersion)
	b.WriteByte(byte(r.CommandCode))
	binary.Write(b, binary.BigEndian, uint16(len(ops)))

	b.Write(r.Endpoint.Marshal6(0))
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

func NewAuthenticationReply() *AuthenticationReply {
	return &AuthenticationReply{
		Options: NewOptionSet(),
	}
}
func NewAuthenticationReplyWithType(typ AuthenticationReplyType) *AuthenticationReply {
	ar := NewAuthenticationReply()
	ar.Type = typ
	return ar
}
func (a *AuthenticationReply) Marshal() []byte {
	ops := a.Options.Marshal()
	b := bytes.Buffer{}

	b.WriteByte(protocolVersion)
	b.WriteByte(byte(a.Type))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	b.Write(ops)
	return b.Bytes()
}
func ParseAuthenticationReplyFrom(b io.Reader) (*AuthenticationReply, error) {
	a := &AuthenticationReply{}

	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)

	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}
	if buf[0] != protocolVersion {
		return nil, NewErrVersionMismatch(int(buf[0]), nil)
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
	Endpoint  *SocksAddr
	Options   *OptionSet
}

func NewOperationReply() *OperationReply {
	return &OperationReply{
		Endpoint: &SocksAddr{
			AddressType: AddressTypeIPv4,
			Address:     []byte{0, 0, 0, 0},
		},
		Options: NewOptionSet(),
	}
}
func NewOperationReplyWithCode(code ReplyCode) *OperationReply {
	rep := NewOperationReply()
	rep.ReplyCode = code
	return rep
}
func (o *OperationReply) Marshal() []byte {
	ops := o.Options.Marshal()

	b := bytes.Buffer{}

	b.WriteByte(protocolVersion)
	b.WriteByte(byte(o.ReplyCode))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	b.Write(o.Endpoint.Marshal6(0))
	b.Write(ops)
	return b.Bytes()
}
func ParseOperationReplyFrom(b io.Reader) (*OperationReply, error) {
	r := &OperationReply{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	// ver cc opLen2
	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}
	if buf[0] != protocolVersion {
		return r, NewErrVersionMismatch(int(buf[0]), nil)
	}
	r.ReplyCode = ReplyCode(buf[1])
	optLen := binary.BigEndian.Uint16(buf[2:])

	addr, _, _, err := ParseSocksAddr6From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	return r, nil
}

type UDPHeaderType byte

const (
	_ UDPHeaderType = iota
	UDPMessageAssociationInit
	UDPMessageAssociationAck
	UDPMessageDatagram
	UDPMessageError
)

type UDPErrorType byte

const (
	_ UDPErrorType = iota
	UDPErrorNetworkUnreachable
	UDPErrorHostUnreachable
	UDPErrorTTLExpired
	UDPErrorDatagramTooBig
)

type UDPMessage struct {
	Type          UDPHeaderType
	AssociationID uint64
	// dgram & icmp
	Endpoint *SocksAddr
	// icmp
	ErrorEndpoint *SocksAddr
	ErrorCode     UDPErrorType
	// dgram
	Data []byte
}

func (u *UDPMessage) Marshal() []byte {
	b := bytes.Buffer{}

	switch u.Type {
	case UDPMessageAssociationInit, UDPMessageAssociationAck:
		b.WriteByte(protocolVersion)
		b.WriteByte(byte(u.Type))
		binary.Write(&b, binary.BigEndian, uint16(12))
		binary.Write(&b, binary.BigEndian, u.AssociationID)
	case UDPMessageDatagram:
		addr := u.Endpoint.Marshal6(0)
		totalLen := 12 + len(addr) + len(u.Data)
		b.WriteByte(protocolVersion)
		b.WriteByte(byte(u.Type))
		binary.Write(&b, binary.BigEndian, uint16(totalLen))
		binary.Write(&b, binary.BigEndian, u.AssociationID)

		b.Write(addr)
		b.Write(u.Data)
	case UDPMessageError:
		addr := u.Endpoint.Marshal6(0)
		eaddr := u.ErrorEndpoint.Marshal6(byte(u.ErrorCode))
		totalLen := 12 + len(addr) + len(eaddr)

		b.WriteByte(protocolVersion)
		b.WriteByte(byte(u.Type))
		binary.Write(&b, binary.BigEndian, uint16(totalLen))

		binary.Write(&b, binary.BigEndian, u.AssociationID)

		b.Write(addr)
		b.Write(eaddr)
	}
	return b.Bytes()
}

func ParseUDPMessageFrom(b io.Reader) (*UDPMessage, error) {
	u := &UDPMessage{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	if _, err := io.ReadFull(b, buf[:12]); err != nil {
		return nil, err
	}
	if buf[0] != protocolVersion {
		return nil, NewErrVersionMismatch(int(buf[0]), nil)
	}

	totalLen := binary.BigEndian.Uint16(buf[2:])
	remainLen := int(totalLen) - 12
	u.Type = UDPHeaderType(buf[1])
	u.AssociationID = binary.BigEndian.Uint64(buf[4:])

	if u.Type == UDPMessageAssociationInit || u.Type == UDPMessageAssociationAck {
		return u, nil
	}

	addr, _, l, err := ParseSocksAddr6FromWithLimit(b, remainLen)
	if err != nil {
		return nil, err
	}
	u.Endpoint = addr
	remainLen -= l

	if u.Type == UDPMessageDatagram {
		if _, err = io.ReadFull(b, buf[:remainLen]); err != nil {
			return nil, err
		}
		u.Data = internal.Dup(buf[:remainLen])
		return u, nil
	}

	eaddr, uerr, _, err := ParseSocksAddr6FromWithLimit(b, remainLen)
	if err != nil {
		return nil, err
	}
	u.ErrorCode = UDPErrorType(uerr)
	u.ErrorEndpoint = eaddr

	return u, nil
}
