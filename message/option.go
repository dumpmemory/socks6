package message

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
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

	OptionKindSessionRequest:  func(b []byte) (OptionData, error) { return SessionRequestOptionData{}, assertZeroBuffer(b) },
	OptionKindSessionID:       parseSessionIDOptionData,
	OptionKindSessionOK:       func(b []byte) (OptionData, error) { return SessionOKOptionData{}, assertZeroBuffer(b) },
	OptionKindSessionInvalid:  func(b []byte) (OptionData, error) { return SessionInvalidOptionData{}, assertZeroBuffer(b) },
	OptionKindSessionTeardown: func(b []byte) (OptionData, error) { return SessionTeardownOptionData{}, assertZeroBuffer(b) },

	OptionKindTokenRequest:           parseTokenRequestOptionData,
	OptionKindIdempotenceWindow:      parseIdempotenceWindowOptionData,
	OptionKindIdempotenceExpenditure: parseIdempotenceExpenditureOptionData,
	OptionKindIdempotenceAccepted:    func(b []byte) (OptionData, error) { return IdempotenceAcceptedOptionData{}, assertZeroBuffer(b) },
	OptionKindIdempotenceRejected:    func(b []byte) (OptionData, error) { return IdempotenceRejectedOptionData{}, assertZeroBuffer(b) },
}

// SetOptionDataParser set the option data parse function for given kind to fn
// set fn to nil to clear parser
func SetOptionDataParser(kind OptionKind, fn func([]byte) (OptionData, error)) {
	optionDataParseFn[kind] = fn
}

func assertZeroBuffer(b []byte) error {
	if len(b) != 0 {
		return ErrBufferSize.WithVerbose("expect no buffer, actual %d bytes", len(b))
	}
	return nil
}

// kind(i16) length(i16) data(b(length))

// Option represent a SOCKS6 option
type Option struct {
	Kind   OptionKind
	Length uint16
	Data   OptionData
}

// ParseOptionFrom parses b as a SOCKS6 option.
func ParseOptionFrom(b io.Reader) (Option, error) {
	// kind2 length2
	buf := internal.BytesPool64k.Rent()
	defer internal.BytesPool64k.Return(buf)
	if _, err := io.ReadFull(b, buf[:4]); err != nil {
		return Option{}, err
	}

	l := binary.BigEndian.Uint16(buf[2:]) - 4

	t := OptionKind(binary.BigEndian.Uint16(buf))
	parseFn, ok := optionDataParseFn[t]
	if !ok || parseFn == nil {
		parseFn = parseRawOptionData
	}
	if _, err := io.ReadFull(b, buf[:l]); err != nil {
		return Option{}, err
	}
	data := buf[:l]
	opData, err := parseFn(data)
	if err != nil {
		return Option{}, err
	}
	op := Option{
		Kind:   t,
		Length: l + 4,
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
		lg.Panic("too much option data")
	}
	o.Length = uint16(l)
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, o.Kind)
	binary.Write(buf, binary.BigEndian, o.Length)
	buf.Write(data)
	return buf.Bytes()
}

// maybe MarshalTo([]byte)

type OptionData interface {
	Marshal() []byte
}

func overflowCheck(n int) uint16 {
	if n > math.MaxUint16 {
		lg.Panic("too much option data bytes")
	}
	return uint16(n)
}

type RawOptionData struct {
	Data []byte
}

func parseRawOptionData(d []byte) (OptionData, error) {
	return &RawOptionData{Data: internal.Dup(d)}, nil
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
	methodMap := map[byte]bool{}
	idl := binary.BigEndian.Uint16(d)
	for _, v := range d[2:] {
		if v != 0 {
			methodMap[v] = true
		}
	}
	m := make([]byte, len(methodMap))
	i := 0
	for k := range methodMap {
		m[i] = k
		i++
	}
	internal.SortByte(m)
	return AuthenticationMethodAdvertisementOptionData{
		InitialDataLength: idl,
		Methods:           m,
	}, nil
}
func (a AuthenticationMethodAdvertisementOptionData) Len() uint16 {
	l := internal.PaddedLen(len(a.Methods)+2, 4)
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
		return nil, ErrBufferSize.WithVerbose("expect 4 bytes buffer, actual %d bytes", len(d))
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
		Data:   internal.Dup(d[1:]),
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
	return SessionIDOptionData{ID: internal.Dup(d)}, nil
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
		return nil, ErrBufferSize.WithVerbose("expect 4 bytes buffer, actual %d bytes", len(d))
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
		return nil, ErrBufferSize.WithVerbose("expect 8 bytes buffer, actual %d bytes", len(d))
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
		return nil, ErrBufferSize.WithVerbose("expect 4 bytes buffer, actual %d bytes", len(d))
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
