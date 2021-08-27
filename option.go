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

	OptionKindSessionRequest:  func(b []byte) (OptionData, error) { return SessionRequestOptionData{}, bufferLengthPolice(b) },
	OptionKindSessionID:       parseSessionIDOptionData,
	OptionKindSessionOK:       func(b []byte) (OptionData, error) { return SessionOKOptionData{}, bufferLengthPolice(b) },
	OptionKindSessionInvalid:  func(b []byte) (OptionData, error) { return SessionInvalidOptionData{}, bufferLengthPolice(b) },
	OptionKindSessionTeardown: func(b []byte) (OptionData, error) { return SessionTeardownOptionData{}, bufferLengthPolice(b) },

	OptionKindTokenRequest:           parseTokenRequestOptionData,
	OptionKindIdempotenceWindow:      parseIdempotenceWindowOptionData,
	OptionKindIdempotenceExpenditure: parseIdempotenceExpenditureOptionData,
	OptionKindIdempotenceAccepted:    func(b []byte) (OptionData, error) { return IdempotenceAcceptedOptionData{}, bufferLengthPolice(b) },
	OptionKindIdempotenceRejected:    func(b []byte) (OptionData, error) { return IdempotenceRejectedOptionData{}, bufferLengthPolice(b) },
}

// SetOptionDataParser set the option data parse function for given kind to fn
// set fn to nil to clear parser
func SetOptionDataParser(kind OptionKind, fn func([]byte) (OptionData, error)) {
	optionDataParseFn[kind] = fn
}

func bufferLengthPolice(b []byte) error {
	if len(b) != 0 {
		return errProtocolPoliceBufferSize
	}
	return nil
}

// kind(i16) length(i16) data(b(length))

// An Option represent a SOCKS6 option
type Option struct {
	Kind   OptionKind
	Length uint16
	Data   OptionData
}

// ParseOption parses b as a SOCKS6 option.
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
	if !ok || parseFn == nil {
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

// Marshal return option's binary encoding
// When encoding, it will always use OptionData provided length,
// option's Length field is ignored and updated by actual length.
func (o *Option) Marshal() []byte {
	data := o.Data.Marshal()
	l := len(data) + 4
	if l > math.MaxUint16 {
		log.Panic("too much option data")
	}
	o.Length = uint16(l)
	ret := make([]byte, l)
	copy(ret[4:], data)
	binary.BigEndian.PutUint16(ret, uint16(o.Kind))
	binary.BigEndian.PutUint16(ret[2:], o.Length)
	return ret
}

// maybe MarshalTo([]byte)

type OptionData interface {
	Marshal() []byte
}

func overflowCheck(n int) uint16 {
	if n > math.MaxUint16 {
		log.Panic("too much option data bytes")
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
	SortByte(m)
	return AuthenticationMethodAdvertisementOptionData{
		InitialDataLength: idl,
		Methods:           m,
	}, nil
}
func (a AuthenticationMethodAdvertisementOptionData) Len() uint16 {
	l := PaddedLen(len(a.Methods)+2, 4)
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
	if len(d) != 4 {
		return nil, errProtocolPoliceBufferSize
	}
	return AuthenticationMethodSelectionOptionData{
		Method: d[0],
	}, nil
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

func (s SessionRequestOptionData) Marshal() []byte {
	return []byte{}
}

type SessionIDOptionData struct {
	ID []byte
}

func parseSessionIDOptionData(d []byte) (OptionData, error) {
	return SessionIDOptionData{ID: dup(d)}, nil
}
func (s SessionIDOptionData) Marshal() []byte {
	return s.ID
}

type SessionOKOptionData struct{}

func (s SessionOKOptionData) Marshal() []byte {
	return []byte{}
}

type SessionInvalidOptionData struct{}

func (s SessionInvalidOptionData) Marshal() []byte {
	return []byte{}
}

type SessionTeardownOptionData struct{}

func (s SessionTeardownOptionData) Marshal() []byte {
	return []byte{}
}

type TokenRequestOptionData struct {
	WindowSize uint32
}

func parseTokenRequestOptionData(d []byte) (OptionData, error) {
	if len(d) != 4 {
		return nil, errProtocolPoliceBufferSize
	}
	return TokenRequestOptionData{WindowSize: binary.BigEndian.Uint32(d)}, nil
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
	if len(d) != 8 {
		return nil, errProtocolPoliceBufferSize
	}
	return IdempotenceWindowOptionData{
		WindowBase: binary.BigEndian.Uint32(d),
		WindowSize: binary.BigEndian.Uint32(d[4:]),
	}, nil
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
	if len(d) != 4 {
		return nil, errProtocolPoliceBufferSize
	}
	return IdempotenceExpenditureOptionData{Token: binary.BigEndian.Uint32(d)}, nil
}
func (s IdempotenceExpenditureOptionData) Marshal() []byte {
	b := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(b, s.Token)
	return b
}

type IdempotenceAcceptedOptionData struct{}

func (s IdempotenceAcceptedOptionData) Marshal() []byte {
	return []byte{}
}

type IdempotenceRejectedOptionData struct{}

func (s IdempotenceRejectedOptionData) Marshal() []byte {
	return []byte{}
}