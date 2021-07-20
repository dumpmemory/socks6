package socks6

import (
	"encoding/binary"
	"errors"
	"log"
)

const (
	_ uint16 = iota
	K_STACK
	K_AUTH_ADVERTISEMENT
	K_AUTH_SELECTION
	K_AUTH_DATA
	K_SESSION_REQUEST
	K_SESSION_ID
	_
	K_SESSION_OK
	K_SESSION_INVALID
	K_SESSION_TEARDOWN
	K_TOKEN_REQUEST
	K_IDEMPOTENCE_WINDOW
	K_IDEMPOTENCE_EXPENDITURE
	K_IDEMPOTENCE_ACCEPTED
	K_IDEMPOTENCE_REJECTED
)

type Option []byte

func OptionCtor(o Option, kind, length uint16) Option {
	binary.BigEndian.PutUint16(o, kind)
	binary.BigEndian.PutUint16(o[2:], length)
	return o
}
func (o Option) Kind() uint16 {
	return binary.BigEndian.Uint16(o)
}
func (o Option) Length() uint16 {
	return binary.BigEndian.Uint16(o[2:])
}
func (o Option) OptionData() []byte {
	return o[4:]
}
func (o Option) Validate() error {
	if len(o) < int(o.Length()) || o.Length() < 4 {
		return errors.New(ERR_LENGTH)
	}
	return nil
}

const (
	LEG_CLIENT_PROXY byte = 1
	LEG_PROXY_REMOTE byte = 2
	LEG_BOTH         byte = 3
)
const (
	_ byte = iota
	LV_IP
	LV_IPv4
	LV_IPv6
	LV_TCP
	LV_UDP
)
const (
	// lv1
	C_TOS              byte = 1
	C_HAPPY_EYEBALL    byte = 2
	C_TTL              byte = 3
	C_NO_FRAGMENTATION byte = 4
	// lv4
	C_TFO       byte = 1
	C_MULTIPATH byte = 2
	C_BACKLOG   byte = 3
	//lv5
	C_UDP_ERROR   byte = 1
	C_PORT_PARITY byte = 2
)

type StackOption Option

func StackOptionCtor(o Option, leg, level, code byte, length uint16) StackOption {
	OptionCtor(o, K_STACK, length)
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
	return o[6:]
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
	StackOptionCtor(o, leg, LV_IP, C_TOS, 8)
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
	if s.Code() != C_TOS || s.Level() != LV_IP {
		return errors.New(ERR_TYPE)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	HAPPY_EYEBALL_NO  = 0x01
	HAPPY_EYEBALL_YES = 0x02
)

type HappyEyeballOption StackOption

func HappyEyeballOptionCtor(o Option, availability bool) HappyEyeballOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_IP, C_HAPPY_EYEBALL, 8)
	if availability {
		o[6] = HAPPY_EYEBALL_YES
	} else {
		o[6] = HAPPY_EYEBALL_NO
	}
	return HappyEyeballOption(o)
}
func (o HappyEyeballOption) Availability() bool {
	if o[6] == HAPPY_EYEBALL_YES {
		return true
	} else if o[6] == HAPPY_EYEBALL_NO {
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
	if s.Code() != C_HAPPY_EYEBALL || s.Level() != LV_IP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	if o[6] != HAPPY_EYEBALL_YES && o[6] != HAPPY_EYEBALL_NO {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type TTLOption StackOption

func TTLOptionCtor(o Option, leg, ttl byte) TTLOption {
	StackOptionCtor(o, leg, LV_IP, C_TTL, 8)
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
	if s.Code() != C_TTL || s.Level() != LV_IP {
		return errors.New(ERR_TYPE)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	NO_FRAGMENTATION_NO  = 0x01
	NO_FRAGMENTATION_YES = 0x02
)

type NoFragmentationOption StackOption

func NoFragmentationOptionCtor(o Option, leg byte, availability bool) NoFragmentationOption {
	StackOptionCtor(o, leg, LV_IP, C_NO_FRAGMENTATION, 8)
	if availability {
		o[6] = NO_FRAGMENTATION_YES
	} else {
		o[6] = NO_FRAGMENTATION_NO
	}
	return NoFragmentationOption(o)
}
func (o NoFragmentationOption) Availability() bool {
	if o[6] == NO_FRAGMENTATION_YES {
		return true
	} else if o[6] == NO_FRAGMENTATION_NO {
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
	if s.Code() != C_NO_FRAGMENTATION || s.Level() != LV_IP {
		return errors.New(ERR_TYPE)
	}
	if o[6] != NO_FRAGMENTATION_YES && o[6] != NO_FRAGMENTATION_NO {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type TFOOption StackOption

func TFOOptionCtor(o Option, payload_size uint16) TFOOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_TCP, C_TFO, 8)
	binary.BigEndian.PutUint16(o[6:], payload_size)
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
	if s.Code() != C_TFO || s.Level() != LV_TCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	return nil
}

const (
	MULTIPATH_NO  = 0x01
	MULTIPATH_YES = 0x02
)

type MultipathOption StackOption

func MultipathOptionCtor(o Option, availability bool) MultipathOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_TCP, C_MULTIPATH, 8)
	if availability {
		o[6] = MULTIPATH_YES
	} else {
		o[6] = MULTIPATH_NO
	}
	return MultipathOption(o)
}
func (o MultipathOption) Availability() bool {
	if o[6] == MULTIPATH_YES {
		return true
	} else if o[6] == MULTIPATH_NO {
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
	if s.Code() != C_MULTIPATH || s.Level() != LV_TCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	if o[6] != MULTIPATH_YES && o[6] != MULTIPATH_NO {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

type BacklogOption StackOption

func BacklogOptionCtor(o Option, backlog uint16) BacklogOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_TCP, C_BACKLOG, 8)
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
	if s.Code() != C_BACKLOG || s.Level() != LV_TCP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	return nil
}

const (
	UDP_ERROR_NO  = 0x01
	UDP_ERROR_YES = 0x02
)

type UDPErrorOption StackOption

func UDPErrorOptionCtor(o Option, availability bool) UDPErrorOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_UDP, C_UDP_ERROR, 8)
	if availability {
		o[6] = UDP_ERROR_YES
	} else {
		o[6] = UDP_ERROR_NO
	}
	return UDPErrorOption(o)
}
func (o UDPErrorOption) Availability() bool {
	if o[6] == UDP_ERROR_YES {
		return true
	} else if o[6] == UDP_ERROR_NO {
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
	if s.Code() != C_UDP_ERROR || s.Level() != LV_UDP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	if o[6] != UDP_ERROR_YES && o[6] != UDP_ERROR_NO {
		return errors.New(ERR_ENUM)
	}
	if o[7] != 0 {
		return errors.New(ERR_PADDING)
	}
	return nil
}

const (
	PORT_PARITY_NO   = 0
	PORT_PARITY_EVEN = 1
	PORT_PARITY_ODD  = 2

	PORT_PARITY_RESERVE_NO  = 0
	PORT_PARITY_RESERVE_YES = 1
)

type PortParityOption StackOption

func PortParityOptionCtor(o Option, parity byte, reserve bool) PortParityOption {
	StackOptionCtor(o, LEG_PROXY_REMOTE, LV_UDP, C_PORT_PARITY, 8)
	o[6] = parity
	if reserve {
		o[7] = PORT_PARITY_RESERVE_YES
	} else {
		o[7] = PORT_PARITY_RESERVE_NO
	}
	return PortParityOption(o)
}
func (o PortParityOption) Parity() byte {
	return o[6]
}
func (o PortParityOption) Reserve() bool {
	if o[7] == PORT_PARITY_RESERVE_YES {
		return true
	} else if o[7] == PORT_PARITY_RESERVE_NO {
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
	if s.Code() != C_PORT_PARITY || s.Level() != LV_UDP {
		return errors.New(ERR_TYPE)
	}
	if s.Leg() != LEG_PROXY_REMOTE {
		return errors.New(ERR_LEG)
	}
	if o[6] != PORT_PARITY_NO && o[6] != PORT_PARITY_EVEN && o[6] != PORT_PARITY_ODD {
		return errors.New(ERR_ENUM)
	}
	if o[7] != PORT_PARITY_RESERVE_YES && o[7] != PORT_PARITY_RESERVE_NO {
		return errors.New(ERR_ENUM)
	}
	return nil
}

const (
	A_NONE              byte = 0
	A_GSSAPI            byte = 1
	A_USERNAME_PASSWORD byte = 2
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
	OptionCtor(o, K_AUTH_ADVERTISEMENT, uint16(length))
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
	if s.Kind() != K_AUTH_ADVERTISEMENT {
		return errors.New(ERR_TYPE)
	}
	if o.InitialDataLength() > 2^14 {
		return errors.New(ERR_LENGTH)
	}
	return nil
}

type AuthenticationMethodSelectionOption Option

func AuthenticationMethodSelectionOptionCtor(o Option, method byte) AuthenticationMethodSelectionOption {
	OptionCtor(o, K_AUTH_SELECTION, 8)
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
	if s.Kind() != K_AUTH_SELECTION {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type AuthenticationDataOption Option

func AuthenticationDataOptionCtor(o Option, method byte, length uint16) AuthenticationDataOption {
	OptionCtor(o, K_AUTH_DATA, length)
	o[4] = method
	return AuthenticationDataOption(o)
}
func (o AuthenticationDataOption) Method() byte {
	return o[4]
}
func (o AuthenticationDataOption) AuthenticationData() []byte {
	return o[5:]
}
func (o AuthenticationDataOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Kind() != K_AUTH_DATA {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionRequestOption Option

func SessionRequestOptionCtor(o Option) SessionRequestOption {
	OptionCtor(o, K_SESSION_REQUEST, 4)
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
	if s.Kind() != K_SESSION_REQUEST {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionIDOption Option

func SessionIDOptionCtor(o Option, id []byte) SessionIDOption {
	OptionCtor(o, K_SESSION_ID, uint16(len(id)+4))
	copy(o[4:], id)
	return SessionIDOption(o)
}
func (o SessionIDOption) ID() []byte {
	return o[4:]
}
func (o SessionIDOption) Validate() error {
	if err := Option(o).Validate(); err != nil {
		return err
	}
	s := Option(o)
	if s.Length()%4 != 0 {
		return errors.New(ERR_PADDING)
	}
	if s.Kind() != K_SESSION_ID {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionOKOption Option

func SessionOKOptionCtor(o Option) SessionOKOption {
	OptionCtor(o, K_SESSION_OK, 4)
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
	if s.Kind() != K_SESSION_OK {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionInvalidOption Option

func SessionInvalidOptionCtor(o Option) SessionInvalidOption {
	OptionCtor(o, K_SESSION_INVALID, 4)
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
	if s.Kind() != K_SESSION_INVALID {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type SessionTeardownOption Option

func SessionTeardownOptionCtor(o Option) SessionTeardownOption {
	OptionCtor(o, K_SESSION_TEARDOWN, 4)
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
	if s.Kind() != K_SESSION_TEARDOWN {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type TokenRequestOption Option

func TokenRequestOptionCtor(o Option, window_size uint32) TokenRequestOption {
	OptionCtor(o, K_TOKEN_REQUEST, 8)
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
	if s.Kind() != K_TOKEN_REQUEST {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceWindowOption Option

func IdempotenceWindowOptionCtor(o Option, window_base, window_size uint32) IdempotenceWindowOption {
	OptionCtor(o, K_IDEMPOTENCE_WINDOW, 12)
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
	if s.Kind() != K_IDEMPOTENCE_WINDOW {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceExpenditureOption Option

func IdempotenceExpenditureOptionCtor(o Option, token uint32) IdempotenceExpenditureOption {
	OptionCtor(o, K_IDEMPOTENCE_EXPENDITURE, 8)
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
	if s.Kind() != K_IDEMPOTENCE_EXPENDITURE {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceAcceptedOption Option

func IdempotenceAcceptedOptionCtor(o Option) IdempotenceAcceptedOption {
	OptionCtor(o, K_IDEMPOTENCE_ACCEPTED, 4)
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
	if s.Kind() != K_IDEMPOTENCE_ACCEPTED {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type IdempotenceRejectedOption Option

func IdempotenceRejectedOptionCtor(o Option) IdempotenceRejectedOption {
	OptionCtor(o, K_IDEMPOTENCE_REJECTED, 4)
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
	if s.Kind() != K_IDEMPOTENCE_REJECTED {
		return errors.New(ERR_TYPE)
	}
	return nil
}

type UsernamePasswordAuthenticationDataOption AuthenticationDataOption

func UsernamePasswordAuthenticationDataOptionCtor(o Option, username, password []byte) UsernamePasswordAuthenticationDataOption {
	l := len(username) + len(password) + 3 + 5
	length := (l/4 + 1) * 4
	AuthenticationDataOptionCtor(o, A_USERNAME_PASSWORD, uint16(length))
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
	AuthenticationDataOptionCtor(o, A_USERNAME_PASSWORD, 8)
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
