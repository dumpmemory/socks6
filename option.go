package socks6

import (
	"encoding/binary"
	"log"
	"math"
)

type OptionKind uint16

const (
	_ OptionKind = iota
	OptionKindStack
	OptionKindAuthenticationMethodAdvertisement
	OptionKindAuthenticationMethodSelection
	OptionKindAuthenticationData
	OptionKindSessionRequest
	OptionKindSessionID
	_
	OptionKindSessionOK
	OptionKindSessionInvalid
	OptionKindSessionTeardown
	OptionKindTokenRequest
	OptionKindIdempotenceWindow
	OptionKindIdempotenceExpenditure
	OptionKindIdempotenceAccepted
	OptionKindIdempotenceRejected
)

var optionDataParseFn = map[OptionKind]func([]byte) (OptionData, error){
	OptionKindStack: parseStackOptionData,

	OptionKindAuthenticationMethodAdvertisement: parseAuthenticationMethodAdvertisementOptionData,
	OptionKindAuthenticationMethodSelection:     parseAuthenticationMethodSelectionOptionData,
	OptionKindAuthenticationData:                parseAuthenticationDataOptionData,

	OptionKindSessionRequest:  func(b []byte) (OptionData, error) { return SessionRequestOptionData{}, nil },
	OptionKindSessionID:       parseSessionIDOptionData,
	OptionKindSessionOK:       func(b []byte) (OptionData, error) { return SessionOKOptionData{}, nil },
	OptionKindSessionInvalid:  func(b []byte) (OptionData, error) { return SessionInvalidOptionData{}, nil },
	OptionKindSessionTeardown: func(b []byte) (OptionData, error) { return SessionTeardownOptionData{}, nil },

	OptionKindTokenRequest:           parseTokenRequestOptionData,
	OptionKindIdempotenceWindow:      parseIdempotenceWindowOptionData,
	OptionKindIdempotenceExpenditure: parseIdempotenceExpenditureOptionData,
	OptionKindIdempotenceAccepted:    func(b []byte) (OptionData, error) { return IdempotenceAcceptedOptionData{}, nil },
	OptionKindIdempotenceRejected:    func(b []byte) (OptionData, error) { return IdempotenceRejectedOptionData{}, nil },
}

// kind(i16) length(i16) data(b(length))

type Option struct {
	Kind   OptionKind
	Length uint16
	Data   OptionData
}

func ParseOption(b []byte) (Option, error) {
	if len(b) < 4 {
		return Option{}, ErrTooShort{ExpectedLen: 4}
	}

	l := binary.BigEndian.Uint16(b[2:])
	if len(b) < int(l) {
		return Option{}, ErrTooShort{ExpectedLen: int(l)}
	}

	t := OptionKind(binary.BigEndian.Uint16(b))
	parseFn, ok := optionDataParseFn[t]
	if !ok {
		parseFn = parseRawOptionData
	}
	data := b[4:l]
	opData, err := parseFn(data)
	if err != nil {
		return Option{}, err
	}
	op := Option{
		Kind:   t,
		Length: l,
		Data:   opData,
	}
	return op, nil
}

func (o *Option) Marshal() []byte {
	expLen := o.Data.Len() + 4
	if expLen != o.Length {
		o.Length = expLen
	}
	ret := make([]byte, o.Length)
	data := o.Data.Marshal()
	if len(data) != int(expLen) {
		log.Panic("implementation of OptionData have problem")
	}
	copy(ret[4:], data)
	binary.BigEndian.PutUint16(ret, uint16(o.Kind))
	binary.BigEndian.PutUint16(ret[2:], o.Length)
	return ret
}

// maybe MarshalTo([]byte)

type OptionData interface {
	Len() uint16
	Marshal() []byte
}

func overflowCheck(n int) uint16 {
	if n > math.MaxUint16 {
		log.Fatal("too much option data bytes")
	}
	return uint16(n)
}

type RawOptionData struct {
	Data []byte
}

func parseRawOptionData(d []byte) (OptionData, error) {
	return &RawOptionData{Data: dup(d)}, nil
}
func (r RawOptionData) Len() uint16 {
	l := len(r.Data)
	return overflowCheck(l)
}
func (r *RawOptionData) Marshal() []byte {
	return r.Data
}

// initial data(i16) methods(bvary)

type AuthenticationMethodAdvertisementOptionData struct {
	InitialDataLength uint16
	Methods           []byte
}

func parseAuthenticationMethodAdvertisementOptionData(d []byte) (OptionData, error) {
	mm := map[byte]bool{}
	idl := binary.BigEndian.Uint16(d)
	for _, v := range d[2:] {
		if v != 0 {
			mm[v] = true
		}
	}
	m := make([]byte, len(mm))
	i := 0
	for k := range mm {
		m[i] = k
		i++
	}
	return AuthenticationMethodAdvertisementOptionData{
		InitialDataLength: idl,
		Methods:           m,
	}, nil
}
func (a AuthenticationMethodAdvertisementOptionData) Len() uint16 {
	l := paddedLen(len(a.Methods)+2, 4)
	return overflowCheck(l)
}
func (a AuthenticationMethodAdvertisementOptionData) Marshal() []byte {
	b := make([]byte, a.Len())
	binary.BigEndian.PutUint16(b, a.InitialDataLength)
	copy(b[2:], a.Methods)
	return b
}

type AuthenticationMethodSelectionOptionData struct {
	Method byte
}

func parseAuthenticationMethodSelectionOptionData(d []byte) (OptionData, error) {
	return AuthenticationMethodSelectionOptionData{
		Method: d[0],
	}, nil
}
func (s AuthenticationMethodSelectionOptionData) Len() uint16 {
	return 4
}
func (s AuthenticationMethodSelectionOptionData) Marshal() []byte {
	return []byte{s.Method, 0, 0, 0}
}

type AuthenticationDataOptionData struct {
	Method byte
	Data   []byte
}

func parseAuthenticationDataOptionData(d []byte) (OptionData, error) {
	return AuthenticationDataOptionData{
		Method: d[0],
		Data:   dup(d[1:]),
	}, nil
}
func (s AuthenticationDataOptionData) Len() uint16 {
	l := len(s.Data) + 1
	return overflowCheck(l)
}
func (s AuthenticationDataOptionData) Marshal() []byte {
	b := make([]byte, s.Len())
	b[0] = s.Method
	copy(b[1:], s.Data)
	return b
}

type SessionRequestOptionData struct{}

func (s SessionRequestOptionData) Len() uint16 {
	return 0
}
func (s SessionRequestOptionData) Marshal() []byte {
	return []byte{}
}

type SessionIDOptionData struct {
	ID []byte
}

func parseSessionIDOptionData(d []byte) (OptionData, error) {
	return SessionIDOptionData{ID: dup(d)}, nil
}
func (s SessionIDOptionData) Len() uint16 {
	return overflowCheck(len(s.ID))
}
func (s SessionIDOptionData) Marshal() []byte {
	return s.ID
}

type SessionOKOptionData struct{}

func (s SessionOKOptionData) Len() uint16 {
	return 0
}
func (s SessionOKOptionData) Marshal() []byte {
	return []byte{}
}

type SessionInvalidOptionData struct{}

func (s SessionInvalidOptionData) Len() uint16 {
	return 0
}
func (s SessionInvalidOptionData) Marshal() []byte {
	return []byte{}
}

type SessionTeardownOptionData struct{}

func (s SessionTeardownOptionData) Len() uint16 {
	return 0
}
func (s SessionTeardownOptionData) Marshal() []byte {
	return []byte{}
}

type TokenRequestOptionData struct {
	WindowSize uint32
}

func parseTokenRequestOptionData(d []byte) (OptionData, error) {
	return TokenRequestOptionData{WindowSize: binary.BigEndian.Uint32(d)}, nil
}
func (s TokenRequestOptionData) Len() uint16 {
	return 4
}
func (s TokenRequestOptionData) Marshal() []byte {
	b := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(b, s.WindowSize)
	return b
}

type IdempotenceWindowOptionData struct {
	WindowBase uint32
	WindowSize uint32
}

func parseIdempotenceWindowOptionData(d []byte) (OptionData, error) {
	return IdempotenceWindowOptionData{
		WindowBase: binary.BigEndian.Uint32(d),
		WindowSize: binary.BigEndian.Uint32(d[4:]),
	}, nil
}
func (s IdempotenceWindowOptionData) Len() uint16 {
	return 8
}
func (s IdempotenceWindowOptionData) Marshal() []byte {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b, s.WindowBase)
	binary.BigEndian.PutUint32(b[4:], s.WindowSize)
	return b
}

type IdempotenceExpenditureOptionData struct {
	Token uint32
}

func parseIdempotenceExpenditureOptionData(d []byte) (OptionData, error) {
	return IdempotenceExpenditureOptionData{Token: binary.BigEndian.Uint32(d)}, nil
}
func (s IdempotenceExpenditureOptionData) Len() uint16 {
	return 4
}
func (s IdempotenceExpenditureOptionData) Marshal() []byte {
	b := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(b, s.Token)
	return b
}

type IdempotenceAcceptedOptionData struct{}

func (s IdempotenceAcceptedOptionData) Len() uint16 {
	return 0
}
func (s IdempotenceAcceptedOptionData) Marshal() []byte {
	return []byte{}
}

type IdempotenceRejectedOptionData struct{}

func (s IdempotenceRejectedOptionData) Len() uint16 {
	return 0
}
func (s IdempotenceRejectedOptionData) Marshal() []byte {
	return []byte{}
}
