package internal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/internal"
)

func TestByteArrayEqual(t *testing.T) {
	tests := []struct {
		a   []byte
		b   []byte
		ret bool
	}{
		{a: []byte{}, b: []byte{}, ret: true},
		{a: []byte{1}, b: []byte{}, ret: false},
		{a: []byte{1}, b: []byte{1}, ret: true},
		{a: []byte{1, 2}, b: []byte{}, ret: false},
		{a: []byte{1, 2}, b: []byte{1}, ret: false},
		{a: []byte{1, 2}, b: []byte{1, 2}, ret: true},
		{a: []byte{1, 2}, b: []byte{1, 3}, ret: false},
	}
	for _, tt := range tests {
		got := internal.ByteArrayEqual(tt.a, tt.b)
		assert.Equal(t, tt.ret, got)
	}
}

func TestPaddedLen(t *testing.T) {
	assert.EqualValues(t, 0, internal.PaddedLen(0, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(1, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(2, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(3, 4))
	assert.EqualValues(t, 4, internal.PaddedLen(4, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(5, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(6, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(7, 4))
	assert.EqualValues(t, 8, internal.PaddedLen(8, 4))

	assert.EqualValues(t, 0, internal.PaddedLen(0, 5))
	assert.EqualValues(t, 5, internal.PaddedLen(5, 5))
	assert.EqualValues(t, 10, internal.PaddedLen(8, 5))
}
