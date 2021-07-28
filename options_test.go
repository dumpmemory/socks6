package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

// border check for option deserialize is implemented in message deserialize

func TestOption(t *testing.T) {
	op := socks6.Option([]byte{0, 0, 0, 6, 1, 2})
	assert.Equal(t, uint16(6), op.Length())
	assert.Equal(t, uint16(0), op.Kind())
	assert.Equal(t, []byte{1, 2}, op.OptionData())

	buf := make([]byte, 4)
	_, err := socks6.OptionCtor(buf, 1, 4)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 1, 0, 4}, buf)
	_, err = socks6.OptionCtor(buf, 1, 1)
	assert.Equal(t, socks6.ErrFormat, err)
	_, err = socks6.OptionCtor(buf[:1], 1, 4)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}

func TestStackOption(t *testing.T) {
	op := socks6.StackOption([]byte{0, 1, 0, 8, 0b10000001, 2, 3, 4})
	assert.Equal(t, byte(2), op.Code())
	assert.Equal(t, byte(0b10), op.Leg())
	assert.Equal(t, byte(1), op.Level())
	assert.Equal(t, []byte{3, 4}, op.StackOptionData())

	buf := make([]byte, 6)
	_, err := socks6.StackOptionCtor(buf, 0b10, 3, 4, 6)
	assert.Equal(t, []byte{0, 1, 0, 6, 0b1000_0011, 4}, buf)
	assert.Nil(t, err)
	_, err = socks6.StackOptionCtor(buf, 100, 3, 4, 6)
	assert.Equal(t, socks6.ErrEnumValue, err)
	_, err = socks6.StackOptionCtor(buf, 0b10, 3, 4, 3)
	assert.Equal(t, socks6.ErrFormat, err)
	_, err = socks6.StackOptionCtor(buf[:1], 0b10, 3, 4, 6)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 6}, err)
}

func TestTOSOption(t *testing.T) {
	op := socks6.TOSOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 1, 2, 0})
	assert.Equal(t, byte(2), op.TOS())

	buf := make([]byte, 8)
	_, err := socks6.TOSOptionCtor(buf, 0b10, 2)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 1, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.TOSOptionCtor(buf[:1], 0b10, 2)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestHappyEyeballOption(t *testing.T) {
	op := socks6.HappyEyeballOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 2, 2, 0})
	assert.Equal(t, true, op.Availability())
	op = socks6.HappyEyeballOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 2, 1, 0})
	assert.Equal(t, false, op.Availability())
	op = socks6.HappyEyeballOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 2, 3, 0})
	assert.Equal(t, false, op.Availability())

	buf := make([]byte, 8)
	_, err := socks6.HappyEyeballOptionCtor(buf, true)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 2, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.HappyEyeballOptionCtor(buf, false)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 2, 1, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.HappyEyeballOptionCtor(buf[:1], false)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestTTLOption(t *testing.T) {
	op := socks6.TTLOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 3, 2, 0})
	assert.Equal(t, byte(2), op.TTL())

	buf := make([]byte, 8)
	_, err := socks6.TTLOptionCtor(buf, 0b10, 2)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 3, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.TTLOptionCtor(buf[:1], 0b10, 2)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestNoFragmentOption(t *testing.T) {
	op := socks6.NoFragmentationOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 4, 2, 0})
	assert.Equal(t, true, op.Availability())
	op = socks6.NoFragmentationOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 4, 1, 0})
	assert.Equal(t, false, op.Availability())
	op = socks6.NoFragmentationOption([]byte{0, 1, 0, 8, (0b10<<6 | 1), 4, 3, 0})
	assert.Equal(t, false, op.Availability())

	buf := make([]byte, 8)
	_, err := socks6.NoFragmentationOptionCtor(buf, 0b10, true)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 4, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.NoFragmentationOptionCtor(buf, 0b10, false)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0001, 4, 1, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.NoFragmentationOptionCtor(buf[:1], 0b10, false)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestTFOOption(t *testing.T) {
	op := socks6.TFOOption([]byte{0, 1, 0, 8, (0b10<<6 | 4), 1, 0, 5})
	assert.Equal(t, uint16(5), op.PayloadSize())

	buf := make([]byte, 8)
	_, err := socks6.TFOOptionCtor(buf, 2)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0100, 1, 0, 2}, buf)
	assert.Nil(t, err)
	_, err = socks6.TFOOptionCtor(buf[:1], 2)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestMultipathOption(t *testing.T) {
	op := socks6.MultipathOption([]byte{0, 1, 0, 8, (0b10<<6 | 4), 2, 2, 0})
	assert.Equal(t, true, op.Availability())
	op = socks6.MultipathOption([]byte{0, 1, 0, 8, (0b10<<6 | 4), 2, 1, 0})
	assert.Equal(t, false, op.Availability())
	op = socks6.MultipathOption([]byte{0, 1, 0, 8, (0b10<<6 | 4), 2, 3, 0})
	assert.Equal(t, false, op.Availability())

	buf := make([]byte, 8)
	_, err := socks6.MultipathOptionCtor(buf, true)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0100, 2, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.MultipathOptionCtor(buf, false)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0100, 2, 1, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.MultipathOptionCtor(buf[:1], false)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestBacklogOption(t *testing.T) {
	op := socks6.BacklogOption([]byte{0, 1, 0, 8, (0b10<<6 | 4), 3, 0, 5})
	assert.Equal(t, uint16(5), op.Backlog())

	buf := make([]byte, 8)
	_, err := socks6.BacklogOptionCtor(buf, 2)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0100, 3, 0, 2}, buf)
	assert.Nil(t, err)
	_, err = socks6.BacklogOptionCtor(buf[:1], 2)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestUDPErrorOption(t *testing.T) {
	op := socks6.UDPErrorOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 1, 2, 0})
	assert.Equal(t, true, op.Availability())
	op = socks6.UDPErrorOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 1, 1, 0})
	assert.Equal(t, false, op.Availability())
	op = socks6.UDPErrorOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 1, 3, 0})
	assert.Equal(t, false, op.Availability())

	buf := make([]byte, 8)
	_, err := socks6.UDPErrorOptionCtor(buf, true)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0101, 1, 2, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.UDPErrorOptionCtor(buf, false)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0101, 1, 1, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.UDPErrorOptionCtor(buf[:1], false)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestPortParityOption(t *testing.T) {
	op := socks6.PortParityOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 2, 2, 1})
	assert.Equal(t, true, op.Reserve())
	assert.Equal(t, byte(2), op.Parity())
	op = socks6.PortParityOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 2, 1, 2})
	assert.Equal(t, false, op.Reserve())
	op = socks6.PortParityOption([]byte{0, 1, 0, 8, (0b10<<6 | 5), 2, 3, 0})
	assert.Equal(t, false, op.Reserve())

	buf := make([]byte, 8)
	_, err := socks6.PortParityOptionCtor(buf, 1, true)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0101, 2, 1, 1}, buf)
	assert.Nil(t, err)
	_, err = socks6.PortParityOptionCtor(buf, 1, false)
	assert.Equal(t, []byte{0, 1, 0, 8, 0b1000_0101, 2, 1, 0}, buf)
	assert.Nil(t, err)
	_, err = socks6.PortParityOptionCtor(buf[:1], 1, false)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestAuthenticationMethodAdvertisementOption(t *testing.T) {
	op := socks6.AuthenticationMethodAdvertisementOption([]byte{0, 2, 0, 8, 0, 1, 2, 0})
	assert.Equal(t, uint16(1), op.InitialDataLength())
	assert.Equal(t, []byte{2}, op.Methods())

	buf := make([]byte, 12)
	o, err := socks6.AuthenticationMethodAdvertisementOptionCtor(buf, []byte{1, 2, 3}, 5)
	assert.Nil(t, err)
	assert.Equal(t, 12, len(o))
	assert.Equal(t, []byte{0, 2, 0, 12, 0, 5}, buf[:6])
	assert.ElementsMatch(t, []byte{1, 2, 3, 0, 0, 0}, buf[6:12])
	_, err = socks6.AuthenticationMethodAdvertisementOptionCtor(buf[:1], []byte{1, 2, 3}, 0)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 12}, err)
}

func TestAuthenticationMethodSelectionOption(t *testing.T) {
	op := socks6.AuthenticationMethodSelectionOption([]byte{0, 3, 0, 8, 2, 0, 0, 0})
	assert.Equal(t, byte(2), op.Method())

	buf := make([]byte, 8)
	_, err := socks6.AuthenticationMethodSelectionOptionCtor(buf, 1)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 3, 0, 8, 1, 0, 0, 0}, buf)
	_, err = socks6.AuthenticationMethodSelectionOptionCtor(buf[:1], 1)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestAuthenticationDataOption(t *testing.T) {
	op := socks6.AuthenticationDataOption([]byte{0, 4, 0, 8, 1, 1, 2, 3})
	assert.Equal(t, byte(1), op.Method())
	assert.Equal(t, []byte{1, 2, 3}, op.AuthenticationData())

	buf := make([]byte, 8)
	_, err := socks6.AuthenticationDataOptionCtor(buf, 1, 8)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 4, 0, 8, 1, 0, 0, 0}, buf)
	_, err = socks6.AuthenticationDataOptionCtor(buf[:1], 1, 8)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestSessionRequestOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.SessionRequestOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 5, 0, 4}, buf)
	_, err = socks6.SessionRequestOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}

func TestSessionIDOption(t *testing.T) {
	op := socks6.SessionIDOption([]byte{0, 6, 0, 8, 1, 2, 3, 4})
	assert.Equal(t, []byte{1, 2, 3, 4}, op.ID())

	buf := make([]byte, 8)
	_, err := socks6.SessionIDOptionCtor(buf, []byte{1, 2, 3, 4})
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 6, 0, 8, 1, 2, 3, 4}, buf)
	_, err = socks6.SessionIDOptionCtor(buf[:1], []byte{1, 2, 3, 4})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestSessionOKOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.SessionOKOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 8, 0, 4}, buf)
	_, err = socks6.SessionOKOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}

func TestSessionInvalidOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.SessionInvalidOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 9, 0, 4}, buf)
	_, err = socks6.SessionInvalidOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}

func TestSessionTeardownOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.SessionTeardownOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 10, 0, 4}, buf)
	_, err = socks6.SessionTeardownOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}

func TestTokenRequestOption(t *testing.T) {
	op := socks6.TokenRequestOption([]byte{0, 11, 0, 8, 0, 0, 1, 0})
	assert.Equal(t, uint32(256), op.WindowSize())

	buf := make([]byte, 8)
	_, err := socks6.TokenRequestOptionCtor(buf, 256)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 11, 0, 8, 0, 0, 1, 0}, buf)
	_, err = socks6.TokenRequestOptionCtor(buf[:1], 256)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestIdempotenceWindowOption(t *testing.T) {
	op := socks6.IdempotenceWindowOption([]byte{0, 12, 0, 12, 0, 0, 1, 0, 0, 0, 2, 0})
	assert.Equal(t, uint32(256), op.WindowBase())
	assert.Equal(t, uint32(512), op.WindowSize())

	buf := make([]byte, 12)
	_, err := socks6.IdempotenceWindowOptionCtor(buf, 256, 512)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 12, 0, 12, 0, 0, 1, 0, 0, 0, 2, 0}, buf)
	_, err = socks6.IdempotenceWindowOptionCtor(buf[:1], 256, 512)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 12}, err)
}

func TestIdempotenceExpenditureOption(t *testing.T) {
	op := socks6.IdempotenceExpenditureOption([]byte{0, 13, 0, 8, 0, 0, 1, 0})
	assert.Equal(t, uint32(256), op.Token())

	buf := make([]byte, 8)
	_, err := socks6.IdempotenceExpenditureOptionCtor(buf, 256)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 13, 0, 8, 0, 0, 1, 0}, buf)
	_, err = socks6.IdempotenceExpenditureOptionCtor(buf[:1], 256)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 8}, err)
}

func TestIdempotenceAcceptedOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.IdempotenceAcceptedOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 14, 0, 4}, buf)
	_, err = socks6.IdempotenceAcceptedOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}
func TestIdempotenceRejectedOption(t *testing.T) {
	buf := make([]byte, 4)
	_, err := socks6.IdempotenceRejectedOptionCtor(buf)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0, 15, 0, 4}, buf)
	_, err = socks6.IdempotenceRejectedOptionCtor(buf[:1])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)
}
