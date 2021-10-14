package internal

import (
	"io"
	"sort"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/internal/lg"
)

func ByteArrayEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Dup create a duplicate of input byte array
func Dup(i []byte) []byte {
	o := make([]byte, len(i))
	copy(o, i)
	return o
}

func PaddedLen(l int, align int) int {
	return (l + align - 1) / align * align
}

// SortByte ascending sort a byte array in position
func SortByte(b []byte) {
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
}

// Must2 passthrough first parameter, panic when second parameter is not nil
//
// Example:
//
// size:=Must2(conn.Write(data)).(int)
func Must2(v interface{}, e error) interface{} {
	if e != nil {
		lg.Panic(e)
	}
	return v
}

func AssertRead(t assert.TestingT, r io.Reader, b []byte) {
	b2 := Dup(b)
	_, err := io.ReadFull(r, b2)
	assert.Nil(t, err)
	assert.Equal(t, b, b2)
}

type CancellableDefer struct {
	f      func()
	cancel bool
}

func NewCancellableDefer(f func()) *CancellableDefer {
	return &CancellableDefer{
		f:      f,
		cancel: false,
	}
}

func (c *CancellableDefer) Defer() {
	if c.cancel {
		return
	}
	if c.f != nil {
		c.f()
	}
}

func (c *CancellableDefer) Cancel() {
	c.cancel = true
}
