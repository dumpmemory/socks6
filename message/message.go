// message contains SOCKS 6 wireformat parser and serializer
package message

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/studentmain/socks6/common/lg"
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
	lg.Debug("read request")
	r := &Request{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)

	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	lg.Debug("read request version", buf[0])

	if buf[0] != protocolVersion {
		return r, NewErrVersionMismatch(int(buf[0]), buf[:1])
	}
	// ver cc opLen2
	if _, err := io.ReadFull(b, buf[1:4]); err != nil {
		return nil, err
	}
	lg.Debug("read request command optionsize", buf[:4])

	r.CommandCode = CommandCode(buf[1])
	optLen := binary.BigEndian.Uint16(buf[2:])

	addr, _, _, err := ParseSocksAddr6From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr
	lg.Debug("read request addr", addr)

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	lg.Debug("read request option", ops)
	return r, nil
}
func (r *Request) Marshal() (buf []byte) {
	lg.Debug("serialize request")
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

	ret := b.Bytes()
	lg.Debugf("serialize request %+v to %+v", r, ret)
	return b.Bytes()
}

func ParseRequest5From(b io.Reader) (*Request, error) {
	lg.Debug("read request5")
	r := &Request{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)

	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	lg.Debug("read request5 version", buf[0])

	if buf[0] != Socks5Version {
		return r, ErrVersionMismatch{Version: int(buf[0]), ConsumedBytes: buf[:1]}
	}
	// ver cc opLen2
	if _, err := io.ReadFull(b, buf[1:2]); err != nil {
		return nil, err
	}
	lg.Debug("read request5 command", buf[:4])

	r.CommandCode = CommandCode(buf[1])
	addr, err := ParseSocksAddr5From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr
	lg.Debug("read request5 addr", addr)

	return r, nil
}

func (r *Request) Marshal5() (buf []byte) {
	lg.Debug("serialize request5")

	b := bytes.NewBuffer(buf)

	b.WriteByte(Socks5Version)
	b.WriteByte(byte(r.CommandCode))
	b.WriteByte(0)
	b.Write(r.Endpoint.Marshal5())

	ret := b.Bytes()
	lg.Debugf("serialize request5 %+v to %+v", r, ret)
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
	lg.Debug("serialize auth reply", a)

	ops := a.Options.Marshal()
	b := bytes.Buffer{}

	b.WriteByte(protocolVersion)
	b.WriteByte(byte(a.Type))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	b.Write(ops)

	ret := b.Bytes()
	lg.Debugf("serialize auth reply %+v to %+v", a, ret)
	return ret
}
func ParseAuthenticationReplyFrom(b io.Reader) (*AuthenticationReply, error) {
	lg.Debug("read auth reply")

	a := &AuthenticationReply{}

	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)

	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return nil, err
	}
	lg.Debug("read auth result optionsize", buf[:4])
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
	lg.Debug("read auth option", ops)

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
	lg.Debug("serialize op reply", o)

	ops := o.Options.Marshal()

	b := bytes.Buffer{}

	b.WriteByte(protocolVersion)
	b.WriteByte(byte(o.ReplyCode))
	binary.Write(&b, binary.BigEndian, uint16(len(ops)))

	b.Write(o.Endpoint.Marshal6(0))
	b.Write(ops)
	ret := b.Bytes()
	lg.Debugf("serialize op reply %+v to %+v", o, ret)
	return ret
}
func ParseOperationReplyFrom(b io.Reader) (*OperationReply, error) {
	lg.Debug("read op reply")

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
	lg.Debug("read op reply command optionsize", buf[:4])

	addr, _, _, err := ParseSocksAddr6From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr
	lg.Debug("read op reply addr", addr)

	ops, err := ParseOptionSetFrom(b, int(optLen))
	if err != nil {
		return nil, err
	}
	r.Options = ops
	lg.Debug("read op reply option", ops)
	return r, nil
}

func (o *OperationReply) Marshal5() []byte {
	lg.Debug("serialize op reply5", o)

	b := bytes.Buffer{}

	b.WriteByte(Socks5Version)
	b.WriteByte(byte(o.ReplyCode))
	b.WriteByte(0)
	b.Write(o.Endpoint.Marshal5())

	ret := b.Bytes()
	lg.Debugf("serialize op reply5 %+v to %+v", o, ret)
	return ret
}
func ParseOperationReply5From(b io.Reader) (*OperationReply, error) {
	lg.Debug("read op reply5")

	r := &OperationReply{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	// ver cc 0
	if _, err := io.ReadFull(b, buf[:3]); err != nil {
		return nil, err
	}
	if buf[0] != Socks5Version {
		return r, NewErrVersionMismatch(int(buf[0]), nil)
	}
	r.ReplyCode = ReplyCode(buf[1])

	addr, err := ParseSocksAddr5From(b)
	if err != nil {
		return nil, err
	}
	r.Endpoint = addr
	lg.Debug("read op reply5 addr", addr)
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
	lg.Debug("serialize udpmsg", u)
	b := bytes.Buffer{}

	switch u.Type {
	case UDPMessageAssociationInit, UDPMessageAssociationAck:
		lg.Debug("serialize udpmsg intack")
		b.WriteByte(protocolVersion)
		b.WriteByte(byte(u.Type))
		binary.Write(&b, binary.BigEndian, uint16(12))
		binary.Write(&b, binary.BigEndian, u.AssociationID)
	case UDPMessageDatagram:
		lg.Debug("serialize udpmsg dgram")
		addr := u.Endpoint.Marshal6(0)
		totalLen := 12 + len(addr) + len(u.Data)
		b.WriteByte(protocolVersion)
		b.WriteByte(byte(u.Type))
		binary.Write(&b, binary.BigEndian, uint16(totalLen))
		binary.Write(&b, binary.BigEndian, u.AssociationID)

		b.Write(addr)
		b.Write(u.Data)
	case UDPMessageError:
		lg.Debug("serialize udpmsg error")
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
	ret := b.Bytes()
	lg.Debugf("serialize udpmsg %v to %v", u, ret)

	return ret
}
func (u *UDPMessage) Marshal5() []byte {
	lg.Debug("serialize udpmsg5", u)
	b := bytes.Buffer{}

	switch u.Type {
	case UDPMessageDatagram:
		lg.Debug("serialize udpmsg5 dgram")
		addr := u.Endpoint.Marshal6(0)
		b.WriteByte(0)
		b.WriteByte(0)
		b.WriteByte(0)

		b.Write(addr)
		b.Write(u.Data)
	default:
		lg.Panic("unsupported in socks5")
	}
	ret := b.Bytes()
	lg.Debugf("serialize udpmsg5 %v to %v", u, ret)

	return ret
}

func ParseUDPMessageFrom(b io.Reader) (*UDPMessage, error) {
	lg.Debug("read udpmsg")
	u := &UDPMessage{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	if _, err := io.ReadFull(b, buf[:12]); err != nil {
		return nil, err
	}
	if buf[0] != protocolVersion {
		return nil, NewErrVersionMismatch(int(buf[0]), nil)
	}
	lg.Debug("read udpmsg header", buf[:12])

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
	lg.Debug("read udpmsg addr", addr)

	if u.Type == UDPMessageDatagram {
		if _, err = io.ReadFull(b, buf[:remainLen]); err != nil {
			return nil, err
		}
		u.Data = internal.Dup(buf[:remainLen])
		lg.Debug("read udpmsg data")
		return u, nil
	}

	eaddr, uerr, _, err := ParseSocksAddr6FromWithLimit(b, remainLen)
	if err != nil {
		return nil, err
	}
	u.ErrorCode = UDPErrorType(uerr)
	u.ErrorEndpoint = eaddr
	lg.Debug("read udpmsg error", uerr, eaddr)

	return u, nil
}
func ParseUDPMessage5From(b io.Reader) (*UDPMessage, error) {
	lg.Debug("read udpmsg5")
	u := &UDPMessage{}
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	if _, err := io.ReadFull(b, buf[:3]); err != nil {
		return nil, err
	}

	u.Type = UDPMessageDatagram
	addr, err := ParseSocksAddr5From(b)
	if err != nil {
		return nil, err
	}
	u.Endpoint = addr
	lg.Debug("read udpmsg5 addr", addr)

	if _, err = io.ReadAll(b); err != nil {
		return nil, err
	}
	lg.Debug("read udpmsg5 data")
	return u, nil
}

type Handshake struct {
	Methods []byte
}

func (h *Handshake) Marshal5() []byte {
	lg.Debug("serialize methodsel")
	if len(h.Methods) > 0xff {
		lg.Panic("too much methods")
	}
	b := bytes.Buffer{}
	b.WriteByte(Socks5Version)
	b.WriteByte(byte(len(h.Methods)))
	b.Write(h.Methods)
	ret := b.Bytes()
	lg.Debugf("serialize methodsel %v to %v", h, ret)
	return ret
}
func ParseHandshake5From(b io.Reader) (*Handshake, error) {
	h := &Handshake{}
	buf := make([]byte, 256)
	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	if buf[0] != Socks5Version {
		return nil, NewErrVersionMismatch(5, buf[:1])
	}
	if _, err := io.ReadFull(b, buf[:1]); err != nil {
		return nil, err
	}
	mlen := buf[0]
	if _, err := io.ReadFull(b, buf[:mlen]); err != nil {
		return nil, err
	}
	h.Methods = internal.Dup(buf[:mlen])
	return h, nil
}

type MethodSelection struct {
	Method byte
}

func (h *MethodSelection) Marshal5() []byte {
	lg.Debug("serialize methodsel")
	b := bytes.Buffer{}
	b.WriteByte(Socks5Version)
	b.WriteByte(byte(h.Method))
	ret := b.Bytes()
	lg.Debugf("serialize methodsel %v to %v", h, ret)
	return ret
}
func ParseMethodSelection5From(b io.Reader) (*MethodSelection, error) {
	h := &MethodSelection{}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(b, buf[:2]); err != nil {
		return nil, err
	}
	if buf[0] != Socks5Version {
		return nil, NewErrVersionMismatch(5, buf[:1])
	}
	h.Method = buf[1]
	return h, nil
}
