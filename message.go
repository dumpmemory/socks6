package socks6

import (
	"encoding"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	ERR_LENGTH  = "length out of range"
	ERR_TYPE    = "type mismatch"
	ERR_LEG     = "stack option wrong leg"
	ERR_PADDING = "padding should be 0"
	ERR_ALIGN   = "not aligned"
	ERR_ENUM    = "unexpected enum value"
	ERR_MAGIC   = "magic number error"
)

type Message interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type Endpoint struct {
	Port        uint16
	AddressType byte
	Address     []byte

	NetString string
}

func (e Endpoint) Network() string {
	return e.NetString
}

func (e Endpoint) String() string {
	var s string
	if e.AddressType == AF_DomainName {
		l := e.Address[0]
		s = string(e.Address[1 : 1+l])
		s = strings.Trim(s, string([]byte{0}))
	} else if e.AddressType == AF_IPv4 {
		ip := net.IP(e.Address[:4])
		s = ip.String()
	} else if e.AddressType == AF_IPv6 {
		ip := net.IP(e.Address[:16])
		s = "[" + ip.String() + "]"
	} else {
		return ""
	}
	return s + ":" + strconv.FormatInt(int64(e.Port), 10)
}
func (e Endpoint) AddressSize() int {
	if e.AddressType == AF_DomainName {
		slen := e.Address[0] + 1
		return int((slen/4 + 1) * 4)
	} else if e.AddressType == AF_IPv4 {
		return 4
	} else if e.AddressType == AF_IPv6 {
		return 16
	} else {
		return -1
	}
}
func (e Endpoint) Padding() int {
	if e.AddressType == AF_DomainName {
		slen := e.Address[0] + 1
		return int(slen % 4)
	}
	return 0
}

const (
	CMD_NOOP byte = iota
	CMD_CONNECT
	CMD_BIND
	CMD_UDP_ASSOCIATE
)
const (
	AF_IPv4       byte = 1
	AF_DomainName byte = 3
	AF_IPv6       byte = 4
)

type Request struct {
	CommandCode byte
	Endpoint    Endpoint

	ClientLegStackOption StackOptionData
	RemoteLegStackOption StackOptionData

	Methods     []byte
	InitialData []byte
	MethodData  map[byte][]byte

	RequestSession  bool
	SessionID       []byte
	RequestTeardown bool

	RequestToken uint32
	UseToken     bool
	TokenToSpend uint32
}

func (r *Request) Serialize(buf []byte) (int, error) {
	buf[0] = 6
	buf[1] = r.CommandCode
	// optionlength, tbd
	binary.BigEndian.PutUint16(buf[4:], r.Endpoint.Port)
	buf[6] = 0
	buf[7] = r.Endpoint.AddressType
	hLen := r.Endpoint.AddressSize() + 8
	pOption := hLen

	if len(r.Methods) > 0 {
		o := AuthenticationMethodAdvertisementOptionCtor(buf[pOption:], r.Methods, len(r.InitialData))
		pOption += int(Option(o).Length())

		for m, md := range r.MethodData {
			o := AuthenticationDataOptionCtor(buf[pOption:], m, uint16(len(md)+5))
			copy(o[5:], md)
			pOption += int(Option(o).Length())
		}
	}
	inSession := true
	if len(r.SessionID) > 0 {
		o := SessionIDOptionCtor(buf[pOption:], r.SessionID)
		pOption += int(Option(o).Length())

		if r.RequestTeardown {
			o := SessionTeardownOptionCtor(buf[pOption:])
			pOption += int(Option(o).Length())
		}
	} else if r.RequestSession {
		o := SessionRequestOptionCtor(buf[pOption:])
		pOption += int(Option(o).Length())
	} else {
		inSession = false
	}

	if inSession {
		if r.RequestToken > 0 {
			o := TokenRequestOptionCtor(buf[pOption:], r.RequestToken)
			pOption += int(Option(o).Length())
		}
		if r.UseToken {
			o := IdempotenceExpenditureOptionCtor(buf[pOption:], r.TokenToSpend)
			pOption += int(Option(o).Length())
		}
	}
	cs, sr, csr := GroupStackOption(r.ClientLegStackOption, r.RemoteLegStackOption)
	l, e := cs.Serialize(buf[pOption:], LEG_CLIENT_PROXY)
	if e != nil {
		return 0, e
	}
	pOption += l
	l, e = sr.Serialize(buf[pOption:], LEG_PROXY_REMOTE)
	if e != nil {
		return 0, e
	}
	pOption += l
	l, e = csr.Serialize(buf[pOption:], LEG_BOTH)
	if e != nil {
		return 0, e
	}
	pOption += l

	pLen := pOption - hLen
	binary.BigEndian.PutUint16(buf[2:], uint16(pLen))

	return pLen + hLen, nil
}

func (r *Request) Deserialize(buf []byte) (int, error) {
	if buf[0] != 6 {
		return 0, errors.New(ERR_MAGIC)
	}
	lInitialData := 0
	r.CommandCode = buf[1]
	lOption := binary.BigEndian.Uint16(buf[2:])
	r.Endpoint = Endpoint{}
	r.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	r.Endpoint.AddressType = buf[7]
	r.Endpoint.Address = buf[8:]
	pOption := r.Endpoint.AddressSize() + 8
	r.ClientLegStackOption = StackOptionData{}
	r.RemoteLegStackOption = StackOptionData{}
	r.MethodData = map[byte][]byte{}
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		if op.Length() > lOption {
			break
		}
		pOption += int(op.Length())
		switch op.Kind() {
		case K_STACK:
			s := StackOption(b)
			if s.Leg()&LEG_CLIENT_PROXY > 0 {
				r.ClientLegStackOption.ApplyOption(s)
			}
			if s.Leg()&LEG_PROXY_REMOTE > 0 {
				r.RemoteLegStackOption.ApplyOption(s)
			}
		case K_AUTH_ADVERTISEMENT:
			a := AuthenticationMethodAdvertisementOption(b)
			r.Methods = a.Methods()
			lInitialData = int(a.InitialDataLength())
		case K_AUTH_DATA:
			d := AuthenticationDataOption(b)
			r.MethodData[d.Method()] = d.AuthenticationData()
		case K_SESSION_REQUEST:
			r.RequestSession = true
		case K_SESSION_ID:
			r.SessionID = SessionIDOption(b).ID()
		case K_SESSION_TEARDOWN:
			r.RequestTeardown = true
		case K_TOKEN_REQUEST:
			r.RequestToken = TokenRequestOption(b).WindowSize()
		case K_IDEMPOTENCE_EXPENDITURE:
			r.UseToken = true
			r.TokenToSpend = IdempotenceExpenditureOption(b).Token()
		}
	}
	if lInitialData > 0 {
		r.InitialData = buf[pOption : pOption+lInitialData]
	}
	return 0, nil
}

type StackOptionData struct {
	TOS          *byte
	HappyEyeball *bool
	TTL          *byte
	DF           *bool
	TFO          *uint16
	MPTCP        *bool
	Backlog      *uint16
	UDPError     *bool
	Parity       *byte
	Reserve      *bool
}

func GroupStackOption(c, r StackOptionData) (StackOptionData, StackOptionData, StackOptionData) {
	cc := StackOptionData{}
	rr := StackOptionData{}
	tt := StackOptionData{}
	if c.TOS != nil && r.TOS != nil && *c.TOS == *r.TOS {
		tt.TOS = c.TOS
	} else {
		cc.TOS = c.TOS
		rr.TOS = r.TOS
	}

	if c.HappyEyeball != nil && r.HappyEyeball != nil && *c.HappyEyeball == *r.HappyEyeball {
		tt.HappyEyeball = c.HappyEyeball
	} else {
		cc.HappyEyeball = c.HappyEyeball
		rr.HappyEyeball = r.HappyEyeball
	}

	if c.TTL != nil && r.TTL != nil && *c.TTL == *r.TTL {
		tt.TTL = c.TTL
	} else {
		cc.TTL = c.TTL
		rr.TTL = r.TTL
	}

	if c.DF != nil && r.DF != nil && *c.DF == *r.DF {
		tt.DF = c.DF
	} else {
		cc.DF = c.DF
		rr.DF = r.DF
	}

	if c.TFO != nil && r.TFO != nil && *c.TFO == *r.TFO {
		tt.TFO = c.TFO
	} else {
		cc.TFO = c.TFO
		rr.TFO = r.TFO
	}

	if c.MPTCP != nil && r.MPTCP != nil && *c.MPTCP == *r.MPTCP {
		tt.MPTCP = c.MPTCP
	} else {
		cc.MPTCP = c.MPTCP
		rr.MPTCP = r.MPTCP
	}

	if c.Backlog != nil && r.Backlog != nil && *c.Backlog == *r.Backlog {
		tt.Backlog = c.Backlog
	} else {
		cc.Backlog = c.Backlog
		rr.Backlog = r.Backlog
	}

	if c.UDPError != nil && r.UDPError != nil && *c.UDPError == *r.UDPError {
		tt.UDPError = c.UDPError
	} else {
		cc.UDPError = c.UDPError
		rr.UDPError = r.UDPError
	}

	if c.Parity != nil && r.Parity != nil && *c.Parity == *r.Parity {
		tt.Parity = c.Parity
	} else {
		cc.Parity = c.Parity
		rr.Parity = r.Parity
	}

	if c.Reserve != nil && r.Reserve != nil && *c.Reserve == *r.Reserve {
		tt.Reserve = c.Reserve
	} else {
		cc.Reserve = c.Reserve
		rr.Reserve = r.Reserve
	}
	return cc, rr, tt
}
func (s *StackOptionData) ApplyOption(o StackOption) {

}
func (s StackOptionData) Serialize(buf []byte, leg byte) (int, error) {
	p := 0
	if s.TOS != nil {
		o := TOSOptionCtor(buf[p:], leg, *s.TOS)
		p += int(Option(o).Length())
	}
	if s.HappyEyeball != nil {
		o := HappyEyeballOptionCtor(buf[p:], *s.HappyEyeball)
		p += int(Option(o).Length())
	}
	if s.TTL != nil {
		o := TTLOptionCtor(buf[p:], leg, *s.TTL)
		p += int(Option(o).Length())
	}
	if s.DF != nil {
		o := NoFragmentationOptionCtor(buf[p:], leg, *s.DF)
		p += int(Option(o).Length())
	}
	if s.TFO != nil {
		o := TFOOptionCtor(buf[p:], *s.TFO)
		p += int(Option(o).Length())
	}
	if s.MPTCP != nil {
		o := MultipathOptionCtor(buf[p:], *s.MPTCP)
		p += int(Option(o).Length())
	}
	if s.Backlog != nil {
		o := BacklogOptionCtor(buf[p:], *s.Backlog)
		p += int(Option(o).Length())
	}
	if s.UDPError != nil {
		o := UDPErrorOptionCtor(buf[p:], *s.UDPError)
		p += int(Option(o).Length())
	}
	if s.Parity != nil && s.Reserve != nil {
		o := PortParityOptionCtor(buf[p:], *s.Parity, *s.Reserve)
		p += int(Option(o).Length())
	}
	return p, nil
}

type VersionMismatchReply struct {
	// v=6
}

const (
	AUTH_SUCCESS = 0
	AUTH_FAIL    = 1
)

type AuthenticationReply struct {
	Type byte
	// options
	SelectedMethod byte
	MethodData     []*AuthenticationDataOption

	InSession    bool
	SessionValid bool

	NewWindowBase uint32
	NewWindowSize uint32
	UsingToken    bool
	TokenValid    bool
}

const (
	RE_SUCCESS byte = iota
	RE_SERVFAIL
	RE_RULE_NOT_ALLOW
	RE_NET_UNREACHABLE
	RE_HOST_UNREACHABLE
	RE_CONNECTION_REFUSED
	RE_TTL_EXPIRE
	RE_ADDRESS_NOT_SUPPORT
	RE_TIMEOUT
)

type OperationReply struct {
	ReplyCode byte
	Endpoint  Endpoint
	// options
	ClientLegStackOption StackOptionData
	RemoteLegStackOption StackOptionData

	SessionID []byte
}

const (
	_ byte = iota
	U_ASSOC_INIT
	U_ASSOC_ACK
	U_DGRAM
	U_ERROR
)

type UDPHeader struct {
	Type          byte
	AssociationID uint64
	Length        uint16
	//
	Endpoint      Endpoint
	ErrorEndpoint Endpoint
}
