package socks6

import (
	"encoding/binary"
	"log"
)

const (
	_ uint16 = iota
	OptionKindStack
	OptionKindAuthenticationMethodAdvertisement
	OptionKindAuthenticationMethodSelection
	OptionKindAuthenticationMethodData
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

type Option []byte

func OptionCtor(o Option, kind, length uint16) (Option, error) {
	if length < 4 {
		return nil, ErrFormat
	}
	if len(o) < int(length) {
		return nil, ErrTooShort{ExpectedLen: int(length)}
	}
	binary.BigEndian.PutUint16(o, kind)
	binary.BigEndian.PutUint16(o[2:], length)
	return o[:length], nil
}
func (o Option) Kind() uint16 {
	return binary.BigEndian.Uint16(o)
}
func (o Option) Length() uint16 {
	return binary.BigEndian.Uint16(o[2:])
}
func (o Option) OptionData() []byte {
	return o[4:o.Length()]
}

const (
	StackOptionLegClientProxy byte = 1
	StackOptionLegProxyRemote byte = 2
	StackOptionLegBoth        byte = 3
)
const (
	_ byte = iota
	StackOptionLevelIP
	StackOptionLevelIPv4
	StackOptionLevelIPv6
	StackOptionLevelTCP
	StackOptionLevelUDP
)
const (
	// lv1
	StackOptionCodeIPTOS          byte = 1
	StackOptionCodeIPHappyEyeball byte = 2
	StackOptionCodeIPTTL          byte = 3
	StackOptionCodeIPDF           byte = 4
	// lv4
	StackOptionCodeTCPTFO       byte = 1
	StackOptionCodeTCPMultipath byte = 2
	StackOptionCodeTCPBacklog   byte = 3
	//lv5
	StackOptionCodeUDPUDPError   byte = 1
	StackOptionCodeUDPPortParity byte = 2
)

type StackOption Option

func StackOptionCtor(o Option, leg, level, code byte, length uint16) (StackOption, error) {
	if leg >= 0b100 || level >= 0b100_0000 || leg == 0 {
		return nil, ErrEnumValue
	}
	if length < 6 {
		return nil, ErrFormat
	}
	_, err := OptionCtor(o, OptionKindStack, length)
	if err != nil {
		return nil, err
	}
	o4 := (leg << 6 & 0b11000000) | (level & 0b00111111)
	o[4] = o4
	o[5] = code
	return StackOption(o), nil
}
func (o StackOption) Leg() byte {
	return (o[4] & 0b11000000) >> 6
}
func (o StackOption) Level() byte {
	return o[4] & 0b00111111
}
func (o StackOption) Code() byte {
	return o[5]
}
func (o StackOption) StackOptionData() []byte {
	return o[6:Option(o).Length()]
}

type TOSOption StackOption

func TOSOptionCtor(o Option, leg, tos byte) (TOSOption, error) {
	_, err := StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPTOS, 8)
	if err != nil {
		return nil, err
	}
	o[6] = tos
	return TOSOption(o), nil
}
func (o TOSOption) TOS() byte {
	return o[6]
}

const (
	stackHappyEyeballOptionNo  = 0x01
	stackHappyEyeballOptionYes = 0x02
)

type HappyEyeballOption StackOption

func HappyEyeballOptionCtor(o Option, availability bool) (HappyEyeballOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelIP, StackOptionCodeIPHappyEyeball, 8)
	if err != nil {
		return nil, err
	}
	if availability {
		o[6] = stackHappyEyeballOptionYes
	} else {
		o[6] = stackHappyEyeballOptionNo
	}
	return HappyEyeballOption(o), nil
}
func (o HappyEyeballOption) Availability() bool {
	if o[6] == stackHappyEyeballOptionYes {
		return true
	} else if o[6] == stackHappyEyeballOptionNo {
		return false
	}
	return false
}

type TTLOption StackOption

func TTLOptionCtor(o Option, leg, ttl byte) (TTLOption, error) {
	_, err := StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPTTL, 8)
	if err != nil {
		return nil, err
	}
	o[6] = ttl
	return TTLOption(o), nil
}
func (o TTLOption) TTL() byte {
	return o[6]
}

const (
	stackDFOptionNo  = 0x01
	stackDFOptionYes = 0x02
)

type NoFragmentationOption StackOption

func NoFragmentationOptionCtor(o Option, leg byte, availability bool) (NoFragmentationOption, error) {
	_, err := StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPDF, 8)
	if err != nil {
		return nil, err
	}
	if availability {
		o[6] = stackDFOptionYes
	} else {
		o[6] = stackDFOptionNo
	}
	return NoFragmentationOption(o), nil
}
func (o NoFragmentationOption) Availability() bool {
	if o[6] == stackDFOptionYes {
		return true
	} else if o[6] == stackDFOptionNo {
		return false
	}
	log.Printf("Invalid no fragmentation availability %d, treat as false", o[6])
	return false
}

type TFOOption StackOption

func TFOOptionCtor(o Option, payloadSize uint16) (TFOOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPTFO, 8)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(o[6:], payloadSize)
	return TFOOption(o), nil
}
func (o TFOOption) PayloadSize() uint16 {
	return binary.BigEndian.Uint16(o[6:])
}

const (
	stackMultipathOptionNo  = 0x01
	stackMultipathOptionYes = 0x02
)

type MultipathOption StackOption

func MultipathOptionCtor(o Option, availability bool) (MultipathOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPMultipath, 8)
	if err != nil {
		return nil, err
	}
	if availability {
		o[6] = stackMultipathOptionYes
	} else {
		o[6] = stackMultipathOptionNo
	}
	return MultipathOption(o), nil
}
func (o MultipathOption) Availability() bool {
	if o[6] == stackMultipathOptionYes {
		return true
	} else if o[6] == stackMultipathOptionNo {
		return false
	}
	log.Printf("Invalid multipath availability %d, treat as false", o[6])
	return false
}

type BacklogOption StackOption

func BacklogOptionCtor(o Option, backlog uint16) (BacklogOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPBacklog, 8)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(o[6:], backlog)
	return BacklogOption(o), nil
}
func (o BacklogOption) Backlog() uint16 {
	return binary.BigEndian.Uint16(o[6:])
}

const (
	stackUDPErrorOptionNo  = 0x01
	stackUDPErrorOptionYes = 0x02
)

type UDPErrorOption StackOption

func UDPErrorOptionCtor(o Option, availability bool) (UDPErrorOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelUDP, StackOptionCodeUDPUDPError, 8)
	if err != nil {
		return nil, err
	}
	if availability {
		o[6] = stackUDPErrorOptionYes
	} else {
		o[6] = stackUDPErrorOptionNo
	}
	return UDPErrorOption(o), nil
}
func (o UDPErrorOption) Availability() bool {
	if o[6] == stackUDPErrorOptionYes {
		return true
	} else if o[6] == stackUDPErrorOptionNo {
		return false
	}
	log.Printf("Invalid udp error availability %d, treat as false", o[6])
	return false
}

const (
	StackPortParityOptionParityNo   = 0
	StackPortParityOptionParityEven = 1
	StackPortParityOptionParityOdd  = 2

	stackPortParityOptionReserveNo  = 0
	stackPortParityOptionReserveYes = 1
)

type PortParityOption StackOption

func PortParityOptionCtor(o Option, parity byte, reserve bool) (PortParityOption, error) {
	_, err := StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelUDP, StackOptionCodeUDPPortParity, 8)
	if err != nil {
		return nil, err
	}
	o[6] = parity
	if reserve {
		o[7] = stackPortParityOptionReserveYes
	} else {
		o[7] = stackPortParityOptionReserveNo
	}
	return PortParityOption(o), nil
}
func (o PortParityOption) Parity() byte {
	return o[6]
}
func (o PortParityOption) Reserve() bool {
	if o[7] == stackPortParityOptionReserveYes {
		return true
	} else if o[7] == stackPortParityOptionReserveNo {
		return false
	}
	log.Printf("Invalid port parity reserve %d, treat as false", o[7])
	return false
}

type AuthenticationMethodAdvertisementOption Option

func AuthenticationMethodAdvertisementOptionCtor(o Option, methods []byte, initial_data_length int) (AuthenticationMethodAdvertisementOption, error) {
	m := map[byte]bool{}
	for _, a := range methods {
		m[a] = true
	}
	lload := len(m) + 2
	// "line count" * 4 + head length
	length := (lload/4+1)*4 + 4
	_, err := OptionCtor(o, OptionKindAuthenticationMethodAdvertisement, uint16(length))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(o[4:], uint16(initial_data_length))

	p := 6
	for k := range m {
		o[p] = k
		p++
	}
	return AuthenticationMethodAdvertisementOption(o), nil
}
func (o AuthenticationMethodAdvertisementOption) Methods() []byte {
	e := len(o)
	for i := 7; i < len(o); i++ {
		if o[i] == 0 {
			e = i
		}
	}
	return o[6:e]
}
func (o AuthenticationMethodAdvertisementOption) InitialDataLength() uint16 {
	return binary.BigEndian.Uint16(o[4:])
}

type AuthenticationMethodSelectionOption Option

func AuthenticationMethodSelectionOptionCtor(o Option, method byte) (AuthenticationMethodSelectionOption, error) {
	_, err := OptionCtor(o, OptionKindAuthenticationMethodSelection, 8)
	if err != nil {
		return nil, err
	}
	o[4] = method
	return AuthenticationMethodSelectionOption(o), nil
}
func (o AuthenticationMethodSelectionOption) Method() byte {
	return o[4]
}

type AuthenticationDataOption Option

func AuthenticationDataOptionCtor(o Option, method byte, length uint16) (AuthenticationDataOption, error) {
	_, err := OptionCtor(o, OptionKindAuthenticationMethodData, length)
	if err != nil {
		return nil, err
	}
	o[4] = method
	return AuthenticationDataOption(o), nil
}
func (o AuthenticationDataOption) Method() byte {
	return o[4]
}
func (o AuthenticationDataOption) AuthenticationData() []byte {
	return o[5:Option(o).Length()]
}

type SessionRequestOption Option

func SessionRequestOptionCtor(o Option) (SessionRequestOption, error) {
	_, err := OptionCtor(o, OptionKindSessionRequest, 4)
	if err != nil {
		return nil, err
	}
	return SessionRequestOption(o), nil
}

type SessionIDOption Option

func SessionIDOptionCtor(o Option, id []byte) (SessionIDOption, error) {
	_, err := OptionCtor(o, OptionKindSessionID, uint16(len(id)+4))
	if err != nil {
		return nil, err
	}
	copy(o[4:], id)
	return SessionIDOption(o), nil
}
func (o SessionIDOption) ID() []byte {
	return o[4:Option(o).Length()]
}

type SessionOKOption Option

func SessionOKOptionCtor(o Option) (SessionOKOption, error) {
	_, err := OptionCtor(o, OptionKindSessionOK, 4)
	if err != nil {
		return nil, err
	}
	return SessionOKOption(o), nil
}

type SessionInvalidOption Option

func SessionInvalidOptionCtor(o Option) (SessionInvalidOption, error) {
	_, err := OptionCtor(o, OptionKindSessionInvalid, 4)
	if err != nil {
		return nil, err
	}
	return SessionInvalidOption(o), nil
}

type SessionTeardownOption Option

func SessionTeardownOptionCtor(o Option) (SessionTeardownOption, error) {
	_, err := OptionCtor(o, OptionKindSessionTeardown, 4)
	if err != nil {
		return nil, err
	}
	return SessionTeardownOption(o), nil
}

type TokenRequestOption Option

func TokenRequestOptionCtor(o Option, window_size uint32) (TokenRequestOption, error) {
	_, err := OptionCtor(o, OptionKindTokenRequest, 8)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(o[4:], window_size)
	return TokenRequestOption(o), nil
}
func (o TokenRequestOption) WindowSize() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}

type IdempotenceWindowOption Option

func IdempotenceWindowOptionCtor(o Option, window_base, window_size uint32) (IdempotenceWindowOption, error) {
	_, err := OptionCtor(o, OptionKindIdempotenceWindow, 12)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(o[4:], window_base)
	binary.BigEndian.PutUint32(o[8:], window_size)
	return IdempotenceWindowOption(o), nil
}

func (o IdempotenceWindowOption) WindowBase() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}
func (o IdempotenceWindowOption) WindowSize() uint32 {
	return binary.BigEndian.Uint32(o[8:])
}

type IdempotenceExpenditureOption Option

func IdempotenceExpenditureOptionCtor(o Option, token uint32) (IdempotenceExpenditureOption, error) {
	_, err := OptionCtor(o, OptionKindIdempotenceExpenditure, 8)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(o[4:], token)
	return IdempotenceExpenditureOption(o), nil
}
func (o IdempotenceExpenditureOption) Token() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}

type IdempotenceAcceptedOption Option

func IdempotenceAcceptedOptionCtor(o Option) (IdempotenceAcceptedOption, error) {
	_, err := OptionCtor(o, OptionKindIdempotenceAccepted, 4)
	if err != nil {
		return nil, err
	}
	return IdempotenceAcceptedOption(o), nil
}

type IdempotenceRejectedOption Option

func IdempotenceRejectedOptionCtor(o Option) (IdempotenceRejectedOption, error) {
	_, err := OptionCtor(o, OptionKindIdempotenceRejected, 4)
	if err != nil {
		return nil, err
	}
	return IdempotenceRejectedOption(o), nil
}
