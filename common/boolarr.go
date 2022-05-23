package common

import (
	"math/bits"

	"github.com/studentmain/socks6/internal"
)

// BoolArr is boolean bit array over []byte (just like Vector<bool> in C++)
type BoolArr []byte

func NewBoolArr(size int) BoolArr {
	l := internal.PaddedLen(size, 8) / 8
	return make([]byte, l)
}

var mask = []byte{
	0b00000001,
	0b00000010,
	0b00000100,
	0b00001000,

	0b00010000,
	0b00100000,
	0b01000000,
	0b10000000,
}

func (b BoolArr) Get(id int) bool {
	idx := id / 8
	off := id % 8

	return b[idx]&mask[off] != 0
}

func (b *BoolArr) Set(id int, val bool) {
	idx := id / 8
	off := id % 8
	bb := *b
	if val {
		bb[idx] |= mask[off]
	} else {
		bb[idx] &= ^mask[off]
	}
}

func (b BoolArr) Length() int {
	return len(b) * 8
}

func (b BoolArr) OnesCount() int {
	n := 0
	for _, v := range b {
		n += bits.OnesCount8(v)
	}
	return n
}
