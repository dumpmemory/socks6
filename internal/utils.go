package internal

import (
	"io"
	"sort"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/common/lg"
)

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
func Must2[T any](v T, e error) T {
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
	f      []func()
	cancel bool
}

func NewCancellableDefer(f func()) *CancellableDefer {
	return &CancellableDefer{
		f:      []func(){f},
		cancel: false,
	}
}

func (c *CancellableDefer) Defer() {
	if c.cancel {
		return
	}
	if c.f != nil {
		for _, v := range c.f {
			v()
		}
	}
}

func (c *CancellableDefer) Cancel() {
	c.cancel = true
}

func (c *CancellableDefer) Add(f func()) {
	c.f = append(c.f, f)
}
