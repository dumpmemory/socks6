package message

import (
	"encoding/binary"

	"github.com/studentmain/socks6/internal"
)

type StackOptionLevel byte

const (
	_ StackOptionLevel = iota
	StackOptionLevelIP
	StackOptionLevelIPv4
	StackOptionLevelIPv6
	StackOptionLevelTCP
	StackOptionLevelUDP
)

type StackOptionCode byte

const (
	// lv1
	StackOptionCodeTOS          StackOptionCode = 1
	StackOptionCodeHappyEyeball StackOptionCode = 2
	StackOptionCodeTTL          StackOptionCode = 3
	StackOptionCodeNoFragment   StackOptionCode = 4
	// lv4
	StackOptionCodeTFO       StackOptionCode = 1
	StackOptionCodeMultipath StackOptionCode = 2
	StackOptionCodeBacklog   StackOptionCode = 3
	//lv5
	StackOptionCodeUDPError   StackOptionCode = 1
	StackOptionCodePortParity StackOptionCode = 2
)
const (
	// lv1
	StackOptionIPTOS          = int(StackOptionLevelIP)*256 + int(StackOptionCodeTOS)
	StackOptionIPHappyEyeball = int(StackOptionLevelIP)*256 + int(StackOptionCodeHappyEyeball)
	StackOptionIPTTL          = int(StackOptionLevelIP)*256 + int(StackOptionCodeTTL)
	StackOptionIPNoFragment   = int(StackOptionLevelIP)*256 + int(StackOptionCodeNoFragment)
	// lv4
	StackOptionTCPTFO       = int(StackOptionLevelTCP)*256 + int(StackOptionCodeTFO)
	StackOptionTCPMultipath = int(StackOptionLevelTCP)*256 + int(StackOptionCodeMultipath)
	StackOptionTCPBacklog   = int(StackOptionLevelTCP)*256 + int(StackOptionCodeBacklog)
	// lv5
	StackOptionUDPUDPError   = int(StackOptionLevelUDP)*256 + int(StackOptionCodeUDPError)
	StackOptionUDPPortParity = int(StackOptionLevelUDP)*256 + int(StackOptionCodePortParity)
)

var stackOptionParseFn = map[int]func([]byte) (StackOptionData, error){
	StackOptionIPTOS: func(b []byte) (StackOptionData, error) {
		return parseUint8StackOption(b, &TOSOptionData{})
	},
	StackOptionIPHappyEyeball: func(b []byte) (StackOptionData, error) {
		return parseBoolStackOption(b, &HappyEyeballOptionData{})
	},
	StackOptionIPTTL: func(b []byte) (StackOptionData, error) {
		return parseUint8StackOption(b, &TTLOptionData{})
	},
	StackOptionIPNoFragment: func(b []byte) (StackOptionData, error) {
		return parseBoolStackOption(b, &NoFragmentationOptionData{})
	},
	StackOptionTCPMultipath: func(b []byte) (StackOptionData, error) {
		return parseBoolStackOption(b, &MultipathOptionData{})
	},
	StackOptionTCPTFO: func(b []byte) (StackOptionData, error) {
		return parseUint16StackOption(b, &TFOOptionData{})
	},
	StackOptionTCPBacklog: func(b []byte) (StackOptionData, error) {
		return parseUint16StackOption(b, &BacklogOptionData{})
	},
	StackOptionUDPUDPError: func(b []byte) (StackOptionData, error) {
		return parseBoolStackOption(b, &UDPErrorOptionData{})
	},
	StackOptionUDPPortParity: parsePortParityOptionData,
}

// SetStackOptionDataParser set the stack option data parse function for given level and code to fn
// set fn to nil to clear parser
func SetStackOptionDataParser(lv StackOptionLevel, code StackOptionCode, fn func([]byte) (StackOptionData, error)) {
	id := StackOptionID(lv, code)
	stackOptionParseFn[id] = fn
}

func StackOptionID(level StackOptionLevel, code StackOptionCode) int {
	return int(level)*256 + int(code)
}
func SplitStackOptionID(id int) (StackOptionLevel, StackOptionCode) {
	h := id / 256
	l := id % 256
	return StackOptionLevel(h), StackOptionCode(l)
}

// remote(i1) client(i1) level(i6) code(i8)

type StackOptionData interface {
	OptionData
	Len() uint16
	GetData() interface{}
	SetData(interface{})
}

type BaseStackOptionData struct {
	ClientLeg bool
	RemoteLeg bool
	Level     StackOptionLevel
	Code      StackOptionCode
	Data      StackOptionData
}

func parseRawOptionDataAsStackOptionData(d []byte) (StackOptionData, error) {
	return &RawOptionData{Data: internal.Dup(d)}, nil
}
func (r RawOptionData) GetData() interface{} {
	return r.Data
}
func (r *RawOptionData) SetData(d interface{}) {
	b := d.([]byte)
	r.Data = internal.Dup(b)
}

func parseStackOptionData(d []byte) (OptionData, error) {
	sod := BaseStackOptionData{}
	legLevel := d[0]
	sod.RemoteLeg = legLevel&0b1000_0000 > 0
	sod.ClientLeg = legLevel&0b0100_0000 > 0
	if !(sod.RemoteLeg || sod.ClientLeg) {
		return nil, ErrStackOptionNoLeg
	}
	sod.Level = StackOptionLevel(legLevel & 0b00_111111)
	sod.Code = StackOptionCode(d[1])
	id := StackOptionID(sod.Level, sod.Code)
	parseFn, ok := stackOptionParseFn[id]
	if !ok || parseFn == nil {
		parseFn = parseRawOptionDataAsStackOptionData
	}
	data, err := parseFn(d[2:])
	if err != nil {
		return nil, err
	}
	sod.Data = data
	return sod, nil
}
func (s BaseStackOptionData) Len() uint16 {
	return s.Data.Len() + 2
}
func (s BaseStackOptionData) Marshal() []byte {
	b := make([]byte, s.Len())
	if s.RemoteLeg {
		b[0] |= 0b1000_0000
	}
	if s.ClientLeg {
		b[0] |= 0b0100_0000
	}
	b[0] |= byte(s.Level)
	b[1] = byte(s.Code)
	copy(b[2:], s.Data.Marshal())
	return b
}

const (
	stackOptionFalse byte = 1
	stackOptionTrue  byte = 2
)

func parseBoolStackOption(d []byte, o boolStackOption) (StackOptionData, error) {
	val := d[0] == stackOptionTrue
	if !val && d[0] != stackOptionFalse {
		return nil, ErrEnumValue.WithVerbose("expect 1-2, actual %d", d[0])
	}
	o.SetBool(val)
	return o, nil
}

type boolStackOption interface {
	StackOptionData
	SetBool(bool)
}

func parseUint8StackOption(d []byte, o uint8StackOption) (StackOptionData, error) {
	o.SetUint8(d[0])
	return o, nil
}

type uint8StackOption interface {
	StackOptionData
	SetUint8(byte)
}

func parseUint16StackOption(d []byte, o uint16StackOption) (StackOptionData, error) {
	o.SetUint16(binary.BigEndian.Uint16(d))
	return o, nil
}

type uint16StackOption interface {
	StackOptionData
	SetUint16(uint16)
}

// tos(i8) reserved(i8)

type TOSOptionData struct {
	TOS byte
}

func (t *TOSOptionData) SetUint8(b byte) {
	t.TOS = b
}

func (t TOSOptionData) Len() uint16 {
	return 2
}
func (t TOSOptionData) Marshal() []byte {
	return []byte{t.TOS, 0}
}
func (t TOSOptionData) GetData() interface{} {
	return t.TOS
}
func (t *TOSOptionData) SetData(d interface{}) {
	t.TOS = d.(byte)
}

type HappyEyeballOptionData struct {
	Availability bool
}

func (t *HappyEyeballOptionData) SetBool(b bool) {
	t.Availability = b
}

func (t HappyEyeballOptionData) Len() uint16 {
	return 2
}
func (t HappyEyeballOptionData) Marshal() []byte {
	val := stackOptionFalse
	if t.Availability {
		val = stackOptionTrue
	}
	return []byte{val, 0}
}
func (t HappyEyeballOptionData) GetData() interface{} {
	return t.Availability
}
func (t *HappyEyeballOptionData) SetData(d interface{}) {
	t.Availability = d.(bool)
}

type TTLOptionData struct {
	TTL byte
}

func (t *TTLOptionData) SetUint8(b byte) {
	t.TTL = b
}

func (t TTLOptionData) Len() uint16 {
	return 2
}
func (t TTLOptionData) Marshal() []byte {
	return []byte{t.TTL, 0}
}
func (t TTLOptionData) GetData() interface{} {
	return t.TTL
}
func (t *TTLOptionData) SetData(d interface{}) {
	t.TTL = d.(byte)
}

type NoFragmentationOptionData struct {
	Availability bool
}

func (t *NoFragmentationOptionData) SetBool(b bool) {
	t.Availability = b
}

func (t NoFragmentationOptionData) Len() uint16 {
	return 2
}
func (t NoFragmentationOptionData) Marshal() []byte {
	val := stackOptionFalse
	if t.Availability {
		val = stackOptionTrue
	}
	return []byte{val, 0}
}
func (t NoFragmentationOptionData) GetData() interface{} {
	return t.Availability
}
func (t *NoFragmentationOptionData) SetData(d interface{}) {
	t.Availability = d.(bool)
}

type TFOOptionData struct {
	PayloadSize uint16
}

func (t *TFOOptionData) SetUint16(b uint16) {
	t.PayloadSize = b
}

func (t TFOOptionData) Len() uint16 {
	return 2
}
func (t TFOOptionData) Marshal() []byte {
	b := []byte{0, 0}
	binary.BigEndian.PutUint16(b, t.PayloadSize)
	return b
}
func (t TFOOptionData) GetData() interface{} {
	return t.PayloadSize
}
func (t *TFOOptionData) SetData(d interface{}) {
	t.PayloadSize = d.(uint16)
}

type MultipathOptionData struct {
	Availability bool
}

func (t *MultipathOptionData) SetBool(b bool) {
	t.Availability = b
}

func (t MultipathOptionData) Len() uint16 {
	return 2
}
func (t MultipathOptionData) Marshal() []byte {
	val := stackOptionFalse
	if t.Availability {
		val = stackOptionTrue
	}
	return []byte{val, 0}
}
func (t MultipathOptionData) GetData() interface{} {
	return t.Availability
}
func (t *MultipathOptionData) SetData(d interface{}) {
	t.Availability = d.(bool)
}

type BacklogOptionData struct {
	Backlog uint16
}

func (t *BacklogOptionData) SetUint16(b uint16) {
	t.Backlog = b
}

func (t BacklogOptionData) Len() uint16 {
	return 2
}
func (t BacklogOptionData) Marshal() []byte {
	b := []byte{0, 0}
	binary.BigEndian.PutUint16(b, t.Backlog)
	return b
}
func (t BacklogOptionData) GetData() interface{} {
	return t.Backlog
}
func (t *BacklogOptionData) SetData(d interface{}) {
	t.Backlog = d.(uint16)
}

type UDPErrorOptionData struct {
	Availability bool
}

func (t *UDPErrorOptionData) SetBool(b bool) {
	t.Availability = b
}

func (t UDPErrorOptionData) Len() uint16 {
	return 2
}
func (t UDPErrorOptionData) Marshal() []byte {
	val := stackOptionFalse
	if t.Availability {
		val = stackOptionTrue
	}
	return []byte{val, 0}
}
func (t UDPErrorOptionData) GetData() interface{} {
	return t.Availability
}
func (t *UDPErrorOptionData) SetData(d interface{}) {
	t.Availability = d.(bool)
}

const (
	StackPortParityOptionParityNo   = 0
	StackPortParityOptionParityEven = 1
	StackPortParityOptionParityOdd  = 2
)

type PortParityOptionData struct {
	Parity  byte
	Reserve bool
}

func parsePortParityOptionData(d []byte) (StackOptionData, error) {
	o := PortParityOptionData{}
	val := d[1] == stackOptionTrue
	if !val && d[1] != stackOptionFalse {
		return nil, ErrEnumValue.WithVerbose("port parity reserve expect 1-2, actual %d", d[1])
	}
	o.Reserve = val
	o.Parity = d[0]
	if o.Parity > 2 {
		return nil, ErrEnumValue.WithVerbose("port parity expect 0-2, actual %d", d[0])
	}
	return &o, nil
}
func (t PortParityOptionData) Len() uint16 {
	return 2
}
func (t PortParityOptionData) Marshal() []byte {
	val := stackOptionFalse
	if t.Reserve {
		val = stackOptionTrue
	}
	return []byte{t.Parity, val}
}
func (t PortParityOptionData) GetData() interface{} {
	return t
}
func (t *PortParityOptionData) SetData(d interface{}) {
	dd := d.(PortParityOptionData)
	t.Parity = dd.Parity
	t.Reserve = dd.Reserve
}
