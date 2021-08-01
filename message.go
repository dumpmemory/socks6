package socks6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"regexp"
	"strings"

	"net"
	"strconv"
)

type ErrTooShort struct {
	ExpectedLen int
}

func (e ErrTooShort) Error() string {
	return "buffer too short, need at least " + strconv.FormatInt(int64(e.ExpectedLen), 10)
}

func (e ErrTooShort) Is(t error) bool {
	_, ok := t.(ErrTooShort)
	return ok
}

func addExpectedLen(e error, l int) error {
	if ets, ok := e.(ErrTooShort); ok {
		return ErrTooShort{ExpectedLen: ets.ExpectedLen + l}
	}
	return e
}

var ErrEnumValue = errors.New("unexpected enum value")
var ErrVersion = errors.New("version is not 6")
var ErrFormat = errors.New("wrong message format")
var ErrAddressTypeNotSupport = errors.New("unknown address type")

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
		return 0, ErrEnumValue
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
		expectedSize := (l + 3) / 4 * 4
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
		return 0, ErrEnumValue
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
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	buf[0] = 6
	buf[1] = r.CommandCode
	// optionlength, tbd
	binary.BigEndian.PutUint16(buf[4:], r.Endpoint.Port)
	buf[6] = 0
	buf[7] = r.Endpoint.AddressType
	hLen, err := r.Endpoint.SerializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8)
	}
	hLen += 8
	pOption := hLen
	if len(r.Methods) > 0 {
		o, err := AuthenticationMethodAdvertisementOptionCtor(buf[pOption:], r.Methods, len(r.InitialData))
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(o).Length())

		for m, md := range r.MethodData {
			o, err := AuthenticationDataOptionCtor(buf[pOption:], m, uint16(len(md)+5))
			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			copy(o[5:], md)
			pOption += int(Option(o).Length())
		}
	}
	inSession := true
	if len(r.SessionID) > 0 {
		o, err := SessionIDOptionCtor(buf[pOption:], r.SessionID)
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(o).Length())

		if r.RequestTeardown {
			o, err := SessionTeardownOptionCtor(buf[pOption:])
			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			pOption += int(Option(o).Length())
		}
	} else if r.RequestSession {
		o, err := SessionRequestOptionCtor(buf[pOption:])
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(o).Length())
	} else {
		inSession = false
	}

	if inSession {
		if r.RequestToken > 0 {
			o, err := TokenRequestOptionCtor(buf[pOption:], r.RequestToken)
			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			pOption += int(Option(o).Length())
		}
		if r.UseToken {
			o, err := IdempotenceExpenditureOptionCtor(buf[pOption:], r.TokenToSpend)
			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			pOption += int(Option(o).Length())
		}
	}
	cs, sr, csr := GroupStackOption(r.ClientLegStackOption, r.RemoteLegStackOption)
	l, err := cs.Serialize(buf[pOption:], StackOptionLegClientProxy)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l
	l, err = sr.Serialize(buf[pOption:], StackOptionLegProxyRemote)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l
	l, err = csr.Serialize(buf[pOption:], StackOptionLegBoth)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l

	pLen := pOption - hLen
	binary.BigEndian.PutUint16(buf[2:], uint16(pLen))

	return pLen + hLen, nil
}

func (r *Request) Deserialize(buf []byte) (int, error) {
	// special case to support fallback
	if len(buf) < 1 {
		return 0, ErrTooShort{ExpectedLen: 1}
	}
	if buf[0] != 6 {
		return 0, ErrVersion
	}
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	lInitialData := 0
	r.CommandCode = buf[1]
	lOption := int(binary.BigEndian.Uint16(buf[2:]))
	r.Endpoint = Endpoint{}
	r.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	r.Endpoint.AddressType = buf[7]
	pOption, err := r.Endpoint.DeserializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8+lOption)
	}
	pOption += 8
	r.ClientLegStackOption = StackOptionData{}
	r.RemoteLegStackOption = StackOptionData{}
	r.MethodData = map[byte][]byte{}
	if lOption+pOption > len(buf) {
		return 0, ErrTooShort{ExpectedLen: lOption + pOption}
	}
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		l := int(op.Length())
		lOption -= l
		pOption += l
		if lOption < 0 {
			return 0, ErrFormat
		}
		switch op.Kind() {
		case OptionKindStack:
			s := StackOption(b)
			if s.Leg()&StackOptionLegClientProxy > 0 {
				r.ClientLegStackOption.ApplyOption(s)
			}
			if s.Leg()&StackOptionLegProxyRemote > 0 {
				r.RemoteLegStackOption.ApplyOption(s)
			}
		case OptionKindAuthenticationMethodAdvertisement:
			a := AuthenticationMethodAdvertisementOption(b)
			r.Methods = a.Methods()
			lInitialData = int(a.InitialDataLength())
		case OptionKindAuthenticationMethodData:
			d := AuthenticationDataOption(b)
			r.MethodData[d.Method()] = d.AuthenticationData()
		case OptionKindSessionRequest:
			r.RequestSession = true
		case OptionKindSessionID:
			r.SessionID = SessionIDOption(b).ID()
		case OptionKindSessionTeardown:
			r.RequestTeardown = true
		case OptionKindTokenRequest:
			r.RequestToken = TokenRequestOption(b).WindowSize()
		case OptionKindIdempotenceExpenditure:
			r.UseToken = true
			r.TokenToSpend = IdempotenceExpenditureOption(b).Token()
		}
	}
	if len(buf) < pOption+lInitialData {
		return 0, ErrTooShort{ExpectedLen: pOption + lInitialData}
	}
	if lInitialData > 0 {
		r.InitialData = buf[pOption : pOption+lInitialData]
	}
	return pOption + lInitialData, nil
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
	case StackOptionLevelIP:
		switch o.Code() {
		case StackOptionCodeIPTOS:
			t := TOSOption(o).TOS()
			s.TOS = &t
		case StackOptionCodeIPHappyEyeball:
			a := HappyEyeballOption(o).Availability()
			s.HappyEyeball = &a
		case StackOptionCodeIPTTL:
			t := TTLOption(o).TTL()
			s.TTL = &t
		case StackOptionCodeIPDF:
			a := NoFragmentationOption(o).Availability()
			s.DF = &a
		}
	case StackOptionLevelTCP:
		switch o.Code() {
		case StackOptionCodeTCPTFO:
			p := TFOOption(o).PayloadSize()
			s.TFO = &p
		case StackOptionCodeTCPMultipath:
			a := MultipathOption(o).Availability()
			s.MPTCP = &a
		case StackOptionCodeTCPBacklog:
			b := BacklogOption(o).Backlog()
			s.Backlog = &b
		}
	case StackOptionLevelUDP:
		switch o.Code() {
		case StackOptionCodeUDPUDPError:
			a := UDPErrorOption(o).Availability()
			s.UDPError = &a
		case StackOptionCodeUDPPortParity:
			p := PortParityOption(o)
			pp := p.Parity()
			s.Parity = &pp
			pr := p.Reserve()
			s.Reserve = &pr
		}
	}
}
func (s StackOptionData) Serialize(buf []byte, leg byte) (int, error) {
	p := 0
	if s.TOS != nil {
		o, err := TOSOptionCtor(buf[p:], leg, *s.TOS)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.HappyEyeball != nil {
		o, err := HappyEyeballOptionCtor(buf[p:], *s.HappyEyeball)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.TTL != nil {
		o, err := TTLOptionCtor(buf[p:], leg, *s.TTL)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.DF != nil {
		o, err := NoFragmentationOptionCtor(buf[p:], leg, *s.DF)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.TFO != nil {
		o, err := TFOOptionCtor(buf[p:], *s.TFO)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.MPTCP != nil {
		o, err := MultipathOptionCtor(buf[p:], *s.MPTCP)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.Backlog != nil {
		o, err := BacklogOptionCtor(buf[p:], *s.Backlog)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.UDPError != nil {
		o, err := UDPErrorOptionCtor(buf[p:], *s.UDPError)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	if s.Parity != nil && s.Reserve != nil {
		o, err := PortParityOptionCtor(buf[p:], *s.Parity, *s.Reserve)
		if err != nil {
			return 0, addExpectedLen(err, p)
		}
		p += int(Option(o).Length())
	}
	return p, nil
}

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

func (a *AuthenticationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ErrTooShort{ExpectedLen: 4}
	}
	buf[0] = 6
	buf[1] = a.Type
	pOption := 4
	if a.SelectedMethod != AuthenticationMethodNone {
		o, err := AuthenticationMethodSelectionOptionCtor(buf[pOption:], a.SelectedMethod)
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(o).Length())
	}
	for m, d := range a.MethodData {
		o, err := AuthenticationDataOptionCtor(buf[pOption:], m, uint16(len(d)))
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(o).Length())
		copy(o[4:], d)
	}
	if a.InSession {
		var err error
		if a.SessionValid {
			_, err = SessionOKOptionCtor(buf[pOption:])
		} else {
			_, err = SessionInvalidOptionCtor(buf[pOption:])
		}
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += 4
		if a.NewWindowSize > 0 {
			o, err := IdempotenceWindowOptionCtor(buf[pOption:], a.NewWindowBase, a.NewWindowSize)
			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			pOption += int(Option(o).Length())
		}
		if a.UsingToken {

			if a.TokenValid {
				_, err = IdempotenceAcceptedOptionCtor(buf[pOption:])
			} else {
				_, err = IdempotenceRejectedOptionCtor(buf[pOption:])
			}

			if err != nil {
				return 0, addExpectedLen(err, pOption)
			}
			pOption += 4
		}
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
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		l := int(Option(b).Length())
		pOption += l
		lOption -= l
		if lOption < 0 {
			return 0, ErrFormat
		}
		switch op.Kind() {
		case OptionKindAuthenticationMethodData:
			d := AuthenticationDataOption(b)
			a.MethodData[d.Method()] = d.AuthenticationData()
		case OptionKindAuthenticationMethodSelection:
			s := AuthenticationMethodSelectionOption(b)
			a.SelectedMethod = s.Method()
		case OptionKindSessionOK:
			a.SessionValid = true
		case OptionKindSessionInvalid:
			a.SessionValid = false
		case OptionKindIdempotenceAccepted:
			a.TokenValid = true
		case OptionKindIdempotenceRejected:
			a.TokenValid = false
		case OptionKindIdempotenceWindow:
			i := IdempotenceWindowOption(b)
			a.NewWindowBase = i.WindowBase()
			a.NewWindowSize = i.WindowSize()
		}
	}
	return int(lOption) + 4, nil
}

type OperationReply struct {
	ReplyCode byte
	Endpoint  Endpoint
	// options
	ClientLegStackOption StackOptionData
	RemoteLegStackOption StackOptionData

	SessionID []byte
}

func (o *OperationReply) Serialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	buf[0] = 6
	buf[1] = o.ReplyCode
	binary.BigEndian.PutUint16(buf[4:], o.Endpoint.Port)
	buf[7] = o.Endpoint.AddressType

	eLen, err := o.Endpoint.SerializeAddress(buf[8:])
	if err != nil {
		if ets, ok := err.(ErrTooShort); ok {
			return 0, ErrTooShort{ExpectedLen: ets.ExpectedLen + 8}
		}
		return 0, err
	}
	pOption := eLen + 8
	if len(o.SessionID) > 0 {
		op, err := SessionIDOptionCtor(buf[pOption:], o.SessionID)
		if err != nil {
			return 0, addExpectedLen(err, pOption)
		}
		pOption += int(Option(op).Length())
	}
	cs, sr, csr := GroupStackOption(o.ClientLegStackOption, o.RemoteLegStackOption)
	l, err := cs.Serialize(buf[pOption:], StackOptionLegClientProxy)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l
	l, err = sr.Serialize(buf[pOption:], StackOptionLegClientProxy)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l
	l, err = csr.Serialize(buf[pOption:], StackOptionLegClientProxy)
	if err != nil {
		return 0, addExpectedLen(err, pOption)
	}
	pOption += l
	binary.BigEndian.PutUint16(buf[2:], uint16(pOption-8-eLen))
	return pOption, nil
}
func (o *OperationReply) Deserialize(buf []byte) (int, error) {
	if len(buf) < 10 {
		return 0, ErrTooShort{ExpectedLen: 10}
	}
	if buf[0] != 0 {
		return 0, ErrFormat
	}
	o.ReplyCode = buf[1]
	lOption := int(binary.BigEndian.Uint16(buf[2:]))
	o.Endpoint = Endpoint{}
	o.Endpoint.Port = binary.BigEndian.Uint16(buf[4:])
	o.Endpoint.AddressType = buf[7]
	lAddr, err := o.Endpoint.DeserializeAddress(buf[8:])
	if err != nil {
		return 0, addExpectedLen(err, 8+lOption)
	}
	if len(buf) < lAddr+lOption+8 {
		return 0, ErrTooShort{ExpectedLen: lAddr + lOption + 8}
	}

	o.ClientLegStackOption = StackOptionData{}
	o.RemoteLegStackOption = StackOptionData{}

	pOption := lAddr + 8
	for lOption >= 4 {
		b := buf[pOption:]
		op := Option(b)
		l := int(op.Length())
		lOption -= l
		pOption += l
		if lOption < 0 {
			return 0, ErrFormat
		}
		switch op.Kind() {
		case OptionKindStack:
			s := StackOption(b)
			if s.Leg()&StackOptionLegClientProxy > 0 {
				o.ClientLegStackOption.ApplyOption(s)
			}
			if s.Leg()&StackOptionLegProxyRemote > 0 {
				o.RemoteLegStackOption.ApplyOption(s)
			}
		case OptionKindSessionID:
			o.SessionID = SessionIDOption(b).ID()
		}
	}
	return pOption, nil
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
