package socks6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
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
	//encoding.BinaryMarshaler
	//encoding.BinaryUnmarshaler

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
	switch e.AddressType {
	case AF_DomainName:
		s = string(e.Address)
	case AF_IPv4:
		ip := net.IP(e.Address[:4])
		s = ip.String()
	case AF_IPv6:
		ip := net.IP(e.Address[:16])
		s = "[" + ip.String() + "]"
	default:
		s = ""
	}
	return s + ":" + strconv.FormatInt(int64(e.Port), 10)
}
func (e *Endpoint) DeserializeAddress(b []byte) (int, error) {
	switch e.AddressType {
	case AF_IPv4:
		if len(b) < 4 {
			return 0, errors.New(ERR_LENGTH)
		}
		e.Address = b
		return 4, nil
	case AF_IPv6:
		if len(b) < 16 {
			return 0, errors.New(ERR_LENGTH)
		}
		e.Address = b
		return 16, nil
	case AF_DomainName:
		if len(b) < 2 {
			return 0, errors.New(ERR_LENGTH)
		}
		al := b[0]
		if len(b) < int(al)+1 {
			return 0, errors.New(ERR_LENGTH)
		}
		e.Address = bytes.TrimRight(b[1:al+1], "\u0000")
		return int(al) + 1, nil
	default:
		return 0, errors.New(ERR_ENUM)
	}
}
func (e Endpoint) SerializeAddress(b []byte) (int, error) {
	l := 4
	switch e.AddressType {
	case AF_IPv4:
		l = 4
	case AF_IPv6:
		l = 16
	case AF_DomainName:
		l = len(e.Address) + 1
	}
	if len(b) < l {
		return 0, errors.New(ERR_LENGTH)
	}
	switch e.AddressType {
	case AF_IPv4, AF_IPv6:
		copy(b, e.Address)
		return l, nil
	case AF_DomainName:
		p := l % 4
		if len(b) < l+p {
			return 0, errors.New(ERR_LENGTH)
		}
		for i := 0; i < p; i++ {
			b[l+i] = 0
		}
		copy(b, e.Address)
		return l + p, nil
	default:
		return 0, errors.New(ERR_MAGIC)
	}

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

func (r *Request) BufferSize(buf []byte) int {
	if len(buf) < 12 {
		return 12
	}
	lOption := binary.BigEndian.Uint16(buf[2:])
	lAddr := 4
	switch buf[7] {
	case AF_DomainName:
		lAddr = int(buf[8]) + 1
	case AF_IPv4:
		lAddr = 4
	case AF_IPv6:
		lAddr = 16
	}
	// TODO: initial data
	return int(lOption) + lAddr + 8
}

func (r *Request) Serialize(buf []byte) (int, error) {
	buf[0] = 6
	buf[1] = r.CommandCode
	// optionlength, tbd
	binary.BigEndian.PutUint16(buf[4:], r.Endpoint.Port)
	buf[6] = 0
	buf[7] = r.Endpoint.AddressType
	hLen, err := r.Endpoint.SerializeAddress(buf[8:])
	if err != nil {
		return 0, err
	}
	hLen += 8
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
	pOption, err := r.Endpoint.DeserializeAddress(buf[8:])
	if err != nil {
		return 0, err
	}
	pOption += 8
	r.ClientLegStackOption = StackOptionData{}
	r.RemoteLegStackOption = StackOptionData{}
	r.MethodData = map[byte][]byte{}
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		if op.Length() > lOption {
			break
		}
		lOption -= op.Length()
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
	return pOption, nil
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
	switch o.Level() {
	case LV_IP:
		switch o.Code() {
		case C_TOS:
			*s.TOS = TOSOption(o).TOS()
		case C_HAPPY_EYEBALL:
			*s.HappyEyeball = HappyEyeballOption(o).Availability()
		case C_TTL:
			*s.TTL = TTLOption(o).TTL()
		case C_NO_FRAGMENTATION:
			*s.DF = NoFragmentationOption(o).Availability()
		}
	case LV_TCP:
		switch o.Code() {
		case C_TFO:
			*s.TFO = TFOOption(o).PayloadSize()
		case C_MULTIPATH:
			*s.MPTCP = MultipathOption(o).Availability()
		case C_BACKLOG:
			*s.Backlog = BacklogOption(o).Backlog()
		}
	case LV_UDP:
		switch o.Code() {
		case C_UDP_ERROR:
			*s.UDPError = UDPErrorOption(o).Availability()
		case C_PORT_PARITY:
			p := PortParityOption(o)
			*s.Parity = p.Parity()
			*s.Reserve = p.Reserve()
		}
	}
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
	MethodData     map[byte][]byte

	InSession    bool
	SessionValid bool

	NewWindowBase uint32
	NewWindowSize uint32
	UsingToken    bool
	TokenValid    bool
}

func (a *AuthenticationReply) BufferSize(buf []byte) int {
	if len(buf) < 4 {
		return 4
	}
	return int(binary.BigEndian.Uint16(buf[2:]) + 4)
}
func (a *AuthenticationReply) Serialize(buf []byte) (int, error) {
	buf[0] = 6
	buf[1] = a.Type
	pOption := 4
	if a.SelectedMethod != A_NONE {
		o := AuthenticationMethodSelectionOptionCtor(buf[pOption:], a.SelectedMethod)
		pOption += int(Option(o).Length())
	}
	for m, d := range a.MethodData {
		o := AuthenticationDataOptionCtor(buf[pOption:], m, uint16(len(d)))
		pOption += int(Option(o).Length())
		copy(o[4:], d)
	}
	if a.InSession {
		if a.SessionValid {
			SessionOKOptionCtor(buf[pOption:])
		} else {
			SessionInvalidOptionCtor(buf[pOption:])
		}
		pOption += 4
		if a.NewWindowSize > 0 {
			o := IdempotenceWindowOptionCtor(buf[pOption:], a.NewWindowBase, a.NewWindowSize)
			pOption += int(Option(o).Length())
		}
		if a.UsingToken {
			if a.TokenValid {
				IdempotenceAcceptedOptionCtor(buf[pOption:])
			} else {
				IdempotenceRejectedOptionCtor(buf[pOption:])
			}
			pOption += 4
		}
	}
	binary.BigEndian.PutUint16(buf[2:], uint16(pOption-4))
	return pOption, nil
}
func (a *AuthenticationReply) Deserialize(buf []byte) (int, error) {
	if buf[0] != 6 {
		return 0, errors.New(ERR_MAGIC)
	}
	a.Type = buf[1]
	lOption := binary.BigEndian.Uint16(buf[2:])
	pOption := 4
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		pOption += int(op.Length())
		lOption -= op.Length()
		switch op.Kind() {
		case K_AUTH_DATA:
			d := AuthenticationDataOption(b)
			a.MethodData[d.Method()] = d.AuthenticationData()
		case K_AUTH_SELECTION:
			s := AuthenticationMethodSelectionOption(b)
			a.SelectedMethod = s.Method()
		case K_SESSION_OK:
			a.SessionValid = true
		case K_SESSION_INVALID:
			a.SessionValid = false
		case K_IDEMPOTENCE_ACCEPTED:
			a.TokenValid = true
		case K_IDEMPOTENCE_REJECTED:
			a.TokenValid = false
		case K_IDEMPOTENCE_WINDOW:
			i := IdempotenceWindowOption(b)
			a.NewWindowBase = i.WindowBase()
			a.NewWindowSize = i.WindowSize()
		}
	}
	return int(lOption) + 4, nil
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
