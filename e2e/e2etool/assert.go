package e2etool

import (
	"io"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/internal"
)

func AssertRead(t assert.TestingT, r io.Reader, b []byte) {
	b2 := internal.Dup(b)
	_, err := io.ReadFull(r, b2)
	assert.NoError(t, err)
	assert.Equal(t, b, b2)
}

type canSetDDL interface {
	SetDeadline(t time.Time) error
}

type canSetRDDL interface {
	SetReadDeadline(t time.Time) error
}

func AssertClosed(t assert.TestingT, r io.Reader) {
	after10ms := time.Now().Add(10 * time.Millisecond)
	var err error = nil
	if rr, ok := r.(canSetRDDL); ok {
		err = rr.SetReadDeadline(after10ms)
	} else if rr, ok := r.(canSetDDL); ok {
		err = rr.SetDeadline(after10ms)
	}
	assert.NoError(t, err)
	b := make([]byte, 1)
	n, err := r.Read(b)
	assert.EqualValues(t, 0, n)
	assert.Error(t, err)
}
