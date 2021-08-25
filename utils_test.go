package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
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
		got := socks6.ByteArrayEqual(tt.a, tt.b)
		assert.Equal(t, tt.ret, got)
	}
}

func TestPaddedLen(t *testing.T) {
	assert.EqualValues(t, 0, socks6.PaddedLen(0, 4))
	assert.EqualValues(t, 4, socks6.PaddedLen(1, 4))
	assert.EqualValues(t, 4, socks6.PaddedLen(2, 4))
	assert.EqualValues(t, 4, socks6.PaddedLen(3, 4))
	assert.EqualValues(t, 4, socks6.PaddedLen(4, 4))
	assert.EqualValues(t, 8, socks6.PaddedLen(5, 4))
	assert.EqualValues(t, 8, socks6.PaddedLen(6, 4))
	assert.EqualValues(t, 8, socks6.PaddedLen(7, 4))
	assert.EqualValues(t, 8, socks6.PaddedLen(8, 4))

	assert.EqualValues(t, 0, socks6.PaddedLen(0, 5))
	assert.EqualValues(t, 5, socks6.PaddedLen(5, 5))
	assert.EqualValues(t, 10, socks6.PaddedLen(8, 5))
}
