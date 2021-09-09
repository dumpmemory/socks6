package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/message"
)

func TestOptionSet(t *testing.T) {
	opset := message.NewOptionSet()
	assert.Equal(t, 0, opset.Len())
	opset.Add(message.Option{
		Kind: message.OptionKindSessionOK,
		Data: message.SessionOKOptionData{},
	})
	assert.Equal(t, 1, opset.Len())
	opset.Add(message.Option{
		Kind: message.OptionKindSessionOK,
		Data: message.SessionOKOptionData{},
	})
	assert.Equal(t, 2, opset.Len())
	opset.AddMany([]message.Option{
		{Kind: message.OptionKindSessionInvalid, Data: message.SessionInvalidOptionData{}},
		{Kind: message.OptionKindSessionInvalid, Data: message.SessionInvalidOptionData{}},
	})
	assert.Equal(t, 4, opset.Len())

	assert.Equal(t, []byte{0, 8, 0, 4, 0, 8, 0, 4, 0, 9, 0, 4, 0, 9, 0, 4}, opset.Marshal())
	assert.Equal(t, []byte{0, 8, 0, 4, 0, 8, 0, 4, 0, 9, 0, 4, 0, 9, 0, 4}, opset.Marshal())
	opset.Add(message.Option{
		Kind: message.OptionKindIdempotenceAccepted,
		Data: message.IdempotenceAcceptedOptionData{},
	})
	assert.Equal(t, 5, opset.Len())
	assert.Equal(t, []byte{0, 8, 0, 4, 0, 8, 0, 4, 0, 9, 0, 4, 0, 9, 0, 4, 0, 14, 0, 4}, opset.Marshal())

	_, ok := opset.GetData(message.OptionKindStack)
	assert.False(t, ok)
	data, ok := opset.GetData(message.OptionKindSessionOK)
	assert.True(t, ok)
	assert.Equal(t, message.SessionOKOptionData{}, data)

	ops := opset.GetKind(message.OptionKindStack)
	assert.Equal(t, []message.Option{}, ops)
	ops = opset.GetKind(message.OptionKindSessionInvalid)
	assert.Equal(t,
		[]message.Option{
			{Kind: message.OptionKindSessionInvalid, Data: message.SessionInvalidOptionData{}},
			{Kind: message.OptionKindSessionInvalid, Data: message.SessionInvalidOptionData{}},
		}, ops)

}
