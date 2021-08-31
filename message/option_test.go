package message_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/message"
)

func optionDataTest(t *testing.T, bin []byte, obj message.Option) {
	optionDataTestParse(t, bin, obj)
	optionDataTestMarshal(t, bin, obj)
}
func optionDataTestParse(t *testing.T, bin []byte, obj message.Option) {
	buf := make([]byte, len(bin))
	copy(buf, bin)
	op, err := message.ParseOption(buf)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	assert.Nil(t, err)
	obj.Length = uint16(len(bin))
	assert.Equal(t, obj, op)

	copy(buf, bin)
	b := bytes.NewBuffer(buf)
	op, err = message.ParseOptionFrom(b)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	assert.Nil(t, err)
	obj.Length = uint16(len(bin))
	assert.Equal(t, obj, op)
}
func optionDataTestMarshal(t *testing.T, bin []byte, obj message.Option) {
	obj.Length = uint16(rand.Uint32())
	assert.Equal(t, bin, obj.Marshal())
}
func optionDataTestProtocolPolice(t *testing.T, bin []byte, obj message.Option) {
	buf := make([]byte, len(bin))
	copy(buf, bin)
	op, err := message.ParseOption(buf)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(rand.Uint32())
	}
	// maybe we just want warning
	assert.ErrorIs(t, err, message.ErrProtocolPolice)
	if obj.Data != nil {
		obj.Length = uint16(len(bin))
		assert.Equal(t, obj, op)
	}
}

func TestOption(t *testing.T) {
	_, err := message.ParseOption(nil)
	assert.Error(t, err, message.ErrTooShort{ExpectedLen: 4})
	_, err = message.ParseOption([]byte{0, 0, 0, 100})
	assert.Error(t, err, message.ErrTooShort{ExpectedLen: 100})

	data := []byte{
		255, 255, 0, 12,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	op, err := message.ParseOption(data)
	// byte array should copy from buffer
	data[11] = 10
	assert.Nil(t, err)
	assert.Equal(t, message.Option{
		Kind:   0xffff,
		Length: 12,
		Data: &message.RawOptionData{
			Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, op)
	data[11] = 8
	assert.Equal(t, data, op.Marshal())
	// length is "calculated" "readonly" property
	// only read after parse is reliable
	assert.Equal(t, data, (&message.Option{
		Kind:   0xffff,
		Length: 9961,
		Data: &message.RawOptionData{
			Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		}}).Marshal())
}

func TestRawOptionData(t *testing.T) {
	buf := make([]byte, 114514)

	tooBig := message.RawOptionData{Data: buf}
	assert.Panics(t, func() { tooBig.Len() })

	buf[3] = 9
	d := message.RawOptionData{Data: buf[:4]}
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
	message.SetOptionDataParser(message.OptionKind(512), func(b []byte) (message.OptionData, error) { return MyOptionData{}, nil })
	optionDataTest(t, []byte{2, 0, 0, 4}, message.Option{
		Kind: 512,
		Data: MyOptionData{},
	})
	message.SetOptionDataParser(message.OptionKind(512), nil)
	optionDataTest(t, []byte{2, 0, 0, 4}, message.Option{
		Kind: 512,
		Data: &message.RawOptionData{
			Data: []byte{},
		},
	})
	message.SetOptionDataParser(message.OptionKind(512), func(b []byte) (message.OptionData, error) { return MyBrokenOptionData{}, nil })
	op, _ := message.ParseOption([]byte{2, 0, 0, 4})
	assert.Panics(t, func() { op.Marshal() })
}

func TestAuthenticationMethodAdvertisementOptionData(t *testing.T) {
	optionDataTestParse(t,
		[]byte{
			0, 2, 0, 12,
			0, 100,
			1, 0, 3, 2, 0, 4,
		}, message.Option{
			Kind: message.OptionKindAuthenticationMethodAdvertisement,
			Data: message.AuthenticationMethodAdvertisementOptionData{
				InitialDataLength: 100,
				Methods:           []byte{1, 2, 3, 4},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 2, 0, 8,
			0, 100, 1, 0,
		}, message.Option{
			Kind: message.OptionKindAuthenticationMethodAdvertisement,
			Data: message.AuthenticationMethodAdvertisementOptionData{
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
		}, message.Option{
			Kind: message.OptionKindAuthenticationMethodSelection,
			Data: message.AuthenticationMethodSelectionOptionData{
				Method: 2,
			},
		})
	optionDataTestProtocolPolice(t, []byte{
		0, 3, 0, 5, 1,
	}, message.Option{})
}

func TestAuthenticationDataOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 4, 0, 8,
			2, 3, 2, 1,
		}, message.Option{
			Kind: message.OptionKindAuthenticationData,
			Data: message.AuthenticationDataOptionData{
				Method: 2,
				Data:   []byte{3, 2, 1},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 4, 0, 6,
			2, 1,
		}, message.Option{
			Kind: message.OptionKindAuthenticationData,
			Data: message.AuthenticationDataOptionData{
				Method: 2,
				Data:   []byte{1},
			},
		})
}

func TestSessionRequestOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 5, 0, 4,
		}, message.Option{
			Kind: message.OptionKindSessionRequest,
			Data: message.SessionRequestOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 5, 0, 5, 1,
		}, message.Option{})
}

func TestSessionIDOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 6, 0, 16,
			1, 3, 2, 4, 5, 7, 6, 8, 1, 2, 3, 4,
		}, message.Option{
			Kind: message.OptionKindSessionID,
			Data: message.SessionIDOptionData{
				ID: []byte{1, 3, 2, 4, 5, 7, 6, 8, 1, 2, 3, 4},
			},
		})
}

func TestSessionOKOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 8, 0, 4,
		}, message.Option{
			Kind: message.OptionKindSessionOK,
			Data: message.SessionOKOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 8, 0, 5, 1,
		}, message.Option{})
}
func TestSessionInvalidOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 9, 0, 4,
		}, message.Option{
			Kind: message.OptionKindSessionInvalid,
			Data: message.SessionInvalidOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 9, 0, 5, 1,
		}, message.Option{})
}
func TestSessionSessionTeardownOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 10, 0, 4,
		}, message.Option{
			Kind: message.OptionKindSessionTeardown,
			Data: message.SessionTeardownOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 10, 0, 5, 1,
		}, message.Option{})
}

func TestTokenRequestOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 11, 0, 8,
			0, 0, 2, 0,
		}, message.Option{
			Kind: message.OptionKindTokenRequest,
			Data: message.TokenRequestOptionData{
				WindowSize: 512,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 11, 0, 5, 1,
		}, message.Option{})
}
func TestIdempotenceWindowOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 12, 0, 12,
			0, 0, 1, 0,
			0, 0, 1, 1,
		}, message.Option{
			Kind: message.OptionKindIdempotenceWindow,
			Data: message.IdempotenceWindowOptionData{
				WindowBase: 256,
				WindowSize: 257,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 12, 0, 5, 1,
		}, message.Option{})
}
func TestIdempotenceExpenditureOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 13, 0, 8,
			0, 0, 1, 0,
		}, message.Option{
			Kind: message.OptionKindIdempotenceExpenditure,
			Data: message.IdempotenceExpenditureOptionData{
				Token: 256,
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 13, 0, 5, 1,
		}, message.Option{})
}
func TestIdempotenceAcceptedOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 14, 0, 4,
		}, message.Option{
			Kind: message.OptionKindIdempotenceAccepted,
			Data: message.IdempotenceAcceptedOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 14, 0, 5, 1,
		}, message.Option{})
}

func TestIdempotenceRejectedOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 15, 0, 4,
		}, message.Option{
			Kind: message.OptionKindIdempotenceRejected,
			Data: message.IdempotenceRejectedOptionData{},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 15, 0, 5, 1,
		}, message.Option{})
}
