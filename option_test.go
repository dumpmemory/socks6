package socks6_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

func optionDataTest(t *testing.T, bin []byte, obj socks6.Option) {
	optionDataTestParse(t, bin, obj)
	optionDataTestMarshal(t, bin, obj)
}
func optionDataTestParse(t *testing.T, bin []byte, obj socks6.Option) {
	buf := make([]byte, len(bin))
	copy(buf, bin)
	op, err := socks6.ParseOption(buf)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	assert.Nil(t, err)
	obj.Length = uint16(len(bin))
	assert.Equal(t, obj, op)

	copy(buf, bin)
	b := bytes.NewBuffer(buf)
	op, err = socks6.ParseOptionFrom(b)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	assert.Nil(t, err)
	obj.Length = uint16(len(bin))
	assert.Equal(t, obj, op)
}
func optionDataTestMarshal(t *testing.T, bin []byte, obj socks6.Option) {
	obj.Length = uint16(rand.Uint32())
	assert.Equal(t, bin, obj.Marshal())
}
func optionDataTestProtocolPolice(t *testing.T, bin []byte, obj socks6.Option) {
	buf := make([]byte, len(bin))
	copy(buf, bin)
	op, err := socks6.ParseOption(buf)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	// maybe we just want warning
	assert.ErrorIs(t, err, socks6.ErrProtocolPolice)
	if obj.Data != nil {
		obj.Length = uint16(len(bin))
		assert.Equal(t, obj, op)
	}
}

func TestOption(t *testing.T) {
	_, err := socks6.ParseOption(nil)
	assert.Error(t, err, socks6.ErrTooShort{ExpectedLen: 4})
	_, err = socks6.ParseOption([]byte{0, 0, 0, 100})
	assert.Error(t, err, socks6.ErrTooShort{ExpectedLen: 100})

	data := []byte{
		255, 255, 0, 12,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	op, err := socks6.ParseOption(data)
	// byte array should copy from buffer
	data[11] = 10
	assert.Nil(t, err)
	assert.Equal(t, socks6.Option{
		Kind:   0xffff,
		Length: 12,
		Data: &socks6.RawOptionData{
			Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, op)
	data[11] = 8
	assert.Equal(t, data, op.Marshal())
	// length is "calculated" "readonly" property
	// only read after parse is reliable
	assert.Equal(t, data, (&socks6.Option{
		Kind:   0xffff,
		Length: 9961,
		Data: &socks6.RawOptionData{
			Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		}}).Marshal())
}

func TestRawOptionData(t *testing.T) {
	buf := make([]byte, 114514)

	tooBig := socks6.RawOptionData{Data: buf}
	assert.Panics(t, func() { tooBig.Len() })

	buf[3] = 9
	d := socks6.RawOptionData{Data: buf[:4]}
	assert.EqualValues(t, 4, d.Len())
	assert.Equal(t, []byte{0, 0, 0, 9}, d.Marshal())
}

type MyOptionData struct{}

func (m MyOptionData) Len() uint16 {
	return 0
}
func (m MyOptionData) Marshal() []byte {
	return []byte{}
}

type MyBrokenOptionData struct{}

func (m MyBrokenOptionData) Len() uint16 {
	return 0
}
func (m MyBrokenOptionData) Marshal() []byte {
	return make([]byte, 114514)
}

func TestSetOptionDataParser(t *testing.T) {
	socks6.SetOptionDataParser(socks6.OptionKind(512), func(b []byte) (socks6.OptionData, error) { return MyOptionData{}, nil })
	optionDataTest(t, []byte{2, 0, 0, 4}, socks6.Option{
		Kind: 512,
		Data: MyOptionData{},
	})
	socks6.SetOptionDataParser(socks6.OptionKind(512), nil)
	optionDataTest(t, []byte{2, 0, 0, 4}, socks6.Option{
		Kind: 512,
		Data: &socks6.RawOptionData{
			Data: []byte{},
		},
	})
	socks6.SetOptionDataParser(socks6.OptionKind(512), func(b []byte) (socks6.OptionData, error) { return MyBrokenOptionData{}, nil })
	op, _ := socks6.ParseOption([]byte{2, 0, 0, 4})
	assert.Panics(t, func() { op.Marshal() })
}

func TestAuthenticationMethodAdvertisementOptionData(t *testing.T) {
	optionDataTestParse(t,
		[]byte{
			0, 2, 0, 12,
			0, 100,
			1, 0, 3, 2, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindAuthenticationMethodAdvertisement,
			Data: socks6.AuthenticationMethodAdvertisementOptionData{
				InitialDataLength: 100,
				Methods:           []byte{1, 2, 3, 4},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 2, 0, 8,
			0, 100, 1, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindAuthenticationMethodAdvertisement,
			Data: socks6.AuthenticationMethodAdvertisementOptionData{
				InitialDataLength: 100,
				Methods:           []byte{1},
			},
		})
}

func TestAuthenticationMethodSelectionOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 3, 0, 8,
			2, 0, 0, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindAuthenticationMethodSelection,
			Data: socks6.AuthenticationMethodSelectionOptionData{
				Method: 2,
			},
		})
	optionDataTestProtocolPolice(t, []byte{
		0, 3, 0, 5, 1,
	}, socks6.Option{})
}

func TestAuthenticationDataOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 4, 0, 8,
			2, 3, 2, 1,
		}, socks6.Option{
			Kind: socks6.OptionKindAuthenticationData,
			Data: socks6.AuthenticationDataOptionData{
				Method: 2,
				Data:   []byte{3, 2, 1},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 4, 0, 6,
			2, 1,
		}, socks6.Option{
			Kind: socks6.OptionKindAuthenticationData,
			Data: socks6.AuthenticationDataOptionData{
				Method: 2,
				Data:   []byte{1},
			},
		})
}

func TestSessionRequestOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 5, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindSessionRequest,
			Data: socks6.SessionRequestOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 5, 0, 5, 1,
		}, socks6.Option{})
}

func TestSessionIDOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 6, 0, 16,
			1, 3, 2, 4, 5, 7, 6, 8, 1, 2, 3, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindSessionID,
			Data: socks6.SessionIDOptionData{
				ID: []byte{1, 3, 2, 4, 5, 7, 6, 8, 1, 2, 3, 4},
			},
		})
}

func TestSessionOKOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 8, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindSessionOK,
			Data: socks6.SessionOKOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 8, 0, 5, 1,
		}, socks6.Option{})
}
func TestSessionInvalidOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 9, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindSessionInvalid,
			Data: socks6.SessionInvalidOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 9, 0, 5, 1,
		}, socks6.Option{})
}
func TestSessionSessionTeardownOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 10, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindSessionTeardown,
			Data: socks6.SessionTeardownOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 10, 0, 5, 1,
		}, socks6.Option{})
}

func TestTokenRequestOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 11, 0, 8,
			0, 0, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindTokenRequest,
			Data: socks6.TokenRequestOptionData{
				WindowSize: 512,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 11, 0, 5, 1,
		}, socks6.Option{})
}
func TestIdempotenceWindowOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 12, 0, 12,
			0, 0, 1, 0,
			0, 0, 1, 1,
		}, socks6.Option{
			Kind: socks6.OptionKindIdempotenceWindow,
			Data: socks6.IdempotenceWindowOptionData{
				WindowBase: 256,
				WindowSize: 257,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 12, 0, 5, 1,
		}, socks6.Option{})
}
func TestIdempotenceExpenditureOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 13, 0, 8,
			0, 0, 1, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindIdempotenceExpenditure,
			Data: socks6.IdempotenceExpenditureOptionData{
				Token: 256,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 13, 0, 5, 1,
		}, socks6.Option{})
}
func TestIdempotenceAcceptedOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 14, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindIdempotenceAccepted,
			Data: socks6.IdempotenceAcceptedOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 14, 0, 5, 1,
		}, socks6.Option{})
}

func TestIdempotenceRejectedOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 15, 0, 4,
		}, socks6.Option{
			Kind: socks6.OptionKindIdempotenceRejected,
			Data: socks6.IdempotenceRejectedOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 15, 0, 5, 1,
		}, socks6.Option{})
}
