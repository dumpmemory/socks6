package socks6

import (
	"encoding/binary"
	"errors"
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
	if len(o) < int(length) || length < 4 {
		return nil, errors.New(ERR_LENGTH)
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
func (o Option) Validate() error {
	if len(o) < 4 || len(o) < int(o.Length()) {
		return errors.New(ERR_LENGTH)
	}
	return nil
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

func StackOptionCtor(o Option, leg, level, code byte, length uint16) StackOption {
	OptionCtor(o, OptionKindStack, length)
	o4 := (leg << 6 & 0b11000000) | (level & 0b00111111)
	o[4] = o4
	o[5] = code
	return StackOption(o)
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
func (o StackOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	if Option(o).Kind() != 1 {
		return errors.New(ERR_TYPE)

	}
	if o.Leg() == 0 {
		return errors.New(ERR_LEG)
	}
	return nil
}

type TOSOption StackOption

func TOSOptionCtor(o Option, leg, tos byte) TOSOption {
	StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPTOS, 8)
	o[6] = tos
	return TOSOption(o)
}
func (o TOSOption) TOS() byte {
	return o[6]
}
func (o TOSOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeIPTOS || s.Level() != StackOptionLevelIP {
		return errors.New(ERR_TYPE)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	stackHappyEyeballOptionNo  = 0x01
	stackHappyEyeballOptionYes = 0x02
)

type HappyEyeballOption StackOption

func HappyEyeballOptionCtor(o Option, availability bool) HappyEyeballOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelIP, StackOptionCodeIPHappyEyeball, 8)
	if availability {
		o[6] = stackHappyEyeballOptionYes
	} else {
		o[6] = stackHappyEyeballOptionNo
	}
	return HappyEyeballOption(o)
}
func (o HappyEyeballOption) Availability() bool {
	if o[6] == stackHappyEyeballOptionYes {
		return true
	} else if o[6] == stackHappyEyeballOptionNo {
		return false
	}
	log.Printf("Invalid happy eyeball availability %d, treat as false", o[6])
	return false
}
func (o HappyEyeballOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeIPHappyEyeball || s.Level() != StackOptionLevelIP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	if o[6] != stackHappyEyeballOptionYes && o[6] != stackHappyEyeballOptionNo {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type TTLOption StackOption

func TTLOptionCtor(o Option, leg, ttl byte) TTLOption {
	StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPTTL, 8)
	o[6] = ttl
	return TTLOption(o)
}
func (o TTLOption) TTL() byte {
	return o[6]
}
func (o TTLOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeIPTTL || s.Level() != StackOptionLevelIP {
		return errors.New(ERR_TYPE)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	stackDFOptionNo  = 0x01
	stackDFOptionYes = 0x02
)

type NoFragmentationOption StackOption

func NoFragmentationOptionCtor(o Option, leg byte, availability bool) NoFragmentationOption {
	StackOptionCtor(o, leg, StackOptionLevelIP, StackOptionCodeIPDF, 8)
	if availability {
		o[6] = stackDFOptionYes
	} else {
		o[6] = stackDFOptionNo
	}
	return NoFragmentationOption(o)
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
func (o NoFragmentationOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeIPDF || s.Level() != StackOptionLevelIP {
		return errors.New(ERR_TYPE)
	}
	if o[6] != stackDFOptionYes && o[6] != stackDFOptionNo {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type TFOOption StackOption

func TFOOptionCtor(o Option, payloadSize uint16) TFOOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPTFO, 8)
	binary.BigEndian.PutUint16(o[6:], payloadSize)
	return TFOOption(o)
}
func (o TFOOption) PayloadSize() uint16 {
	return binary.BigEndian.Uint16(o[6:])
}
func (o TFOOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeTCPTFO || s.Level() != StackOptionLevelTCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	return nil
}

const (
	stackMultipathOptionNo  = 0x01
	stackMultipathOptionYes = 0x02
)

type MultipathOption StackOption

func MultipathOptionCtor(o Option, availability bool) MultipathOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPMultipath, 8)
	if availability {
		o[6] = stackMultipathOptionYes
	} else {
		o[6] = stackMultipathOptionNo
	}
	return MultipathOption(o)
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
func (o MultipathOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeTCPMultipath || s.Level() != StackOptionLevelTCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	if o[6] != stackMultipathOptionYes && o[6] != stackMultipathOptionNo {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type BacklogOption StackOption

func BacklogOptionCtor(o Option, backlog uint16) BacklogOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelTCP, StackOptionCodeTCPBacklog, 8)
	binary.BigEndian.PutUint16(o[6:], backlog)
	return BacklogOption(o)
}
func (o BacklogOption) Backlog() uint16 {
	return binary.BigEndian.Uint16(o[6:])
}
func (o BacklogOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeTCPBacklog || s.Level() != StackOptionLevelTCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	return nil
}

const (
	stackUDPErrorOptionNo  = 0x01
	stackUDPErrorOptionYes = 0x02
)

type UDPErrorOption StackOption

func UDPErrorOptionCtor(o Option, availability bool) UDPErrorOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelUDP, StackOptionCodeUDPUDPError, 8)
	if availability {
		o[6] = stackUDPErrorOptionYes
	} else {
		o[6] = stackUDPErrorOptionNo
	}
	return UDPErrorOption(o)
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
func (o UDPErrorOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeUDPUDPError || s.Level() != StackOptionLevelUDP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	if o[6] != stackUDPErrorOptionYes && o[6] != stackUDPErrorOptionNo {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	stackPortParityOptionParityNo   = 0
	stackPortParityOptionParityEven = 1
	stackPortParityOptionParityOdd  = 2

	stackPortParityOptionReserveNo  = 0
	stackPortParityOptionReserveYes = 1
)

type PortParityOption StackOption

func PortParityOptionCtor(o Option, parity byte, reserve bool) PortParityOption {
	StackOptionCtor(o, StackOptionLegProxyRemote, StackOptionLevelUDP, StackOptionCodeUDPPortParity, 8)
	o[6] = parity
	if reserve {
		o[7] = stackPortParityOptionReserveYes
	} else {
		o[7] = stackPortParityOptionReserveNo
	}
	return PortParityOption(o)
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
func (o PortParityOption) Validate() error {
	if err := StackOption(o).Validate(); err != nil {
		return err
	}
	if Option(o).Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	s := StackOption(o)
	if s.Code() != StackOptionCodeUDPPortParity || s.Level() != StackOptionLevelUDP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != StackOptionLegProxyRemote {
		return errors.New(ERR_LEG)
	}
	if o[6] != stackPortParityOptionParityNo && o[6] != stackPortParityOptionParityEven && o[6] != stackPortParityOptionParityOdd {
		return errors.New(ERR_ENUM)
	}
	if o[7] != stackPortParityOptionReserveYes && o[7] != stackPortParityOptionReserveNo {
		return errors.New(ERR_ENUM)
	}
	return nil
}

const (
	AuthenticationMethodNone             byte = 0
	AuthenticationMethodGSSAPI           byte = 1
	AuthenticationMethodUsernamePassword byte = 2
)

type AuthenticationMethodAdvertisementOption Option

func AuthenticationMethodAdvertisementOptionCtor(o Option, methods []byte, initial_data_length int) AuthenticationMethodAdvertisementOption {
	m := map[byte]bool{}
	for _, a := range methods {
		m[a] = true
	}
	lload := len(m) + 2
	// "line count" * 4 + head length
	length := (lload/4+1)*4 + 4
	OptionCtor(o, OptionKindAuthenticationMethodAdvertisement, uint16(length))
	binary.BigEndian.PutUint16(o[4:], uint16(initial_data_length))

	p := 6
	for k := range m {
		o[p] = k
		p++
	}
	return AuthenticationMethodAdvertisementOption(o)
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
func (o AuthenticationMethodAdvertisementOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length()%4 != 0 {
		return errors.New(ERR_PADDING)
	}
	if s.Kind() != OptionKindAuthenticationMethodAdvertisement {
		return errors.New(ERR_TYPE)
	}
	if o.InitialDataLength() > 2^14 {
		return errors.New(ERR_LENGTH)
	}
	return nil
}

type AuthenticationMethodSelectionOption Option

func AuthenticationMethodSelectionOptionCtor(o Option, method byte) AuthenticationMethodSelectionOption {
	OptionCtor(o, OptionKindAuthenticationMethodSelection, 8)
	o[4] = method
	return AuthenticationMethodSelectionOption(o)
}
func (o AuthenticationMethodSelectionOption) Method() byte {
	return o[4]
}
func (o AuthenticationMethodSelectionOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindAuthenticationMethodSelection {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type AuthenticationDataOption Option

func AuthenticationDataOptionCtor(o Option, method byte, length uint16) AuthenticationDataOption {
	OptionCtor(o, OptionKindAuthenticationMethodData, length)
	o[4] = method
	return AuthenticationDataOption(o)
}
func (o AuthenticationDataOption) Method() byte {
	return o[4]
}
func (o AuthenticationDataOption) AuthenticationData() []byte {
	return o[5:Option(o).Length()]
}
func (o AuthenticationDataOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Kind() != OptionKindAuthenticationMethodData {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionRequestOption Option

func SessionRequestOptionCtor(o Option) SessionRequestOption {
	OptionCtor(o, OptionKindSessionRequest, 4)
	return SessionRequestOption(o)
}
func (o SessionRequestOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindSessionRequest {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionIDOption Option

func SessionIDOptionCtor(o Option, id []byte) SessionIDOption {
	OptionCtor(o, OptionKindSessionID, uint16(len(id)+4))
	copy(o[4:], id)
	return SessionIDOption(o)
}
func (o SessionIDOption) ID() []byte {
	return o[4:Option(o).Length()]
}
func (o SessionIDOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length()%4 != 0 {
		return errors.New(ERR_PADDING)
	}
	if s.Kind() != OptionKindSessionID {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionOKOption Option

func SessionOKOptionCtor(o Option) SessionOKOption {
	OptionCtor(o, OptionKindSessionOK, 4)
	return SessionOKOption(o)
}
func (o SessionOKOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindSessionOK {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionInvalidOption Option

func SessionInvalidOptionCtor(o Option) SessionInvalidOption {
	OptionCtor(o, OptionKindSessionInvalid, 4)
	return SessionInvalidOption(o)
}
func (o SessionInvalidOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindSessionInvalid {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionTeardownOption Option

func SessionTeardownOptionCtor(o Option) SessionTeardownOption {
	OptionCtor(o, OptionKindSessionTeardown, 4)
	return SessionTeardownOption(o)
}
func (o SessionTeardownOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindSessionTeardown {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type TokenRequestOption Option

func TokenRequestOptionCtor(o Option, window_size uint32) TokenRequestOption {
	OptionCtor(o, OptionKindTokenRequest, 8)
	binary.BigEndian.PutUint32(o[4:], window_size)
	return TokenRequestOption(o)
}
func (o TokenRequestOption) WindowSize() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}
func (o TokenRequestOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindTokenRequest {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceWindowOption Option

func IdempotenceWindowOptionCtor(o Option, window_base, window_size uint32) IdempotenceWindowOption {
	OptionCtor(o, OptionKindIdempotenceWindow, 12)
	binary.BigEndian.PutUint32(o[4:], window_base)
	binary.BigEndian.PutUint32(o[8:], window_size)
	return IdempotenceWindowOption(o)
}

func (o IdempotenceWindowOption) WindowBase() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}
func (o IdempotenceWindowOption) WindowSize() uint32 {
	return binary.BigEndian.Uint32(o[8:])
}
func (o IdempotenceWindowOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 12 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindIdempotenceWindow {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceExpenditureOption Option

func IdempotenceExpenditureOptionCtor(o Option, token uint32) IdempotenceExpenditureOption {
	OptionCtor(o, OptionKindIdempotenceExpenditure, 8)
	binary.BigEndian.PutUint32(o[4:], token)
	return IdempotenceExpenditureOption(o)
}
func (o IdempotenceExpenditureOption) Token() uint32 {
	return binary.BigEndian.Uint32(o[4:])
}

func (o IdempotenceExpenditureOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 8 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindIdempotenceExpenditure {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceAcceptedOption Option

func IdempotenceAcceptedOptionCtor(o Option) IdempotenceAcceptedOption {
	OptionCtor(o, OptionKindIdempotenceAccepted, 4)
	return IdempotenceAcceptedOption(o)
}

func (o IdempotenceAcceptedOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindIdempotenceAccepted {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceRejectedOption Option

func IdempotenceRejectedOptionCtor(o Option) IdempotenceRejectedOption {
	OptionCtor(o, OptionKindIdempotenceRejected, 4)
	return IdempotenceRejectedOption(o)
}

func (o IdempotenceRejectedOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 4 {
		return errors.New(ERR_LENGTH)
	}
	if s.Kind() != OptionKindIdempotenceRejected {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type UsernamePasswordAuthenticationDataOption AuthenticationDataOption

func UsernamePasswordAuthenticationDataOptionCtor(o Option, username, password []byte) UsernamePasswordAuthenticationDataOption {
	l := len(username) + len(password) + 3 + 5
	length := (l/4 + 1) * 4
	AuthenticationDataOptionCtor(o, AuthenticationMethodUsernamePassword, uint16(length))
	lu := len(username)
	o[5] = 1
	o[6] = byte(lu)
	copy(o[7:], username)
	o[7+lu] = byte(len(password))
	copy(o[8+lu:], password)
	return UsernamePasswordAuthenticationDataOption(o)
}
func (o UsernamePasswordAuthenticationDataOption) Username() []byte {
	l := o[6]
	return o[7 : 7+l]
}
func (o UsernamePasswordAuthenticationDataOption) Password() []byte {
	l2 := o[6]
	s := l2 + 8
	l := o[s-1]
	return o[s : s+l]
}
func (o UsernamePasswordAuthenticationDataOption) Validate() error {
	if err := AuthenticationDataOption(o).Validate(); err != nil {
		return err
	}
	if AuthenticationDataOption(o).Method() != 2 {
		return errors.New(ERR_TYPE)
	}
	s := Option(o)
	if s.Length()%4 != 0 {
		return errors.New(ERR_PADDING)
	}
	if uint16(s.Length())-uint16(len(o.Username())+len(o.Password())+3+5) > 4 {
		return errors.New(ERR_LENGTH)
	}
	if o[5] != 1 {
		return errors.New(ERR_MAGIC)
	}
	if int(o[6]) != len(o.Username()) {
		return errors.New(ERR_LENGTH)
	}
	if int(o[7+len(o.Username())]) != len(o.Password()) {
		return errors.New(ERR_LENGTH)
	}
	return nil
}

const (
	USERNAME_PASSWORD_SUCCESS = 0
	USERNAME_PASSWORD_FAIL    = 1
)

type UsernamePasswordReplyAuthenticationDataOption AuthenticationDataOption

func UsernamePasswordReplyAuthenticationDataOptionCtor(o Option, success bool) UsernamePasswordReplyAuthenticationDataOption {
	AuthenticationDataOptionCtor(o, AuthenticationMethodUsernamePassword, 8)
	o[5] = 1
	if success {
		o[6] = USERNAME_PASSWORD_SUCCESS
	} else {
		o[6] = USERNAME_PASSWORD_FAIL
	}
	return UsernamePasswordReplyAuthenticationDataOption(o)
}
func (o UsernamePasswordReplyAuthenticationDataOption) Success() bool {
	return o[6] == USERNAME_PASSWORD_SUCCESS
}
func (o UsernamePasswordReplyAuthenticationDataOption) Validate() error {
	if err := AuthenticationDataOption(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length() != 8 {
		return errors.New(ERR_PADDING)
	}
	if AuthenticationDataOption(o).Method() != 2 {
		return errors.New(ERR_TYPE)
	}

	if o[5] != 1 {
		return errors.New(ERR_MAGIC)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}
