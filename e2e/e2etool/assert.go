package e2etool

import (
	"bytes"
	"io"
	"sync"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/common/arrayx"
	"github.com/studentmain/socks6/common/rnd"
)

func AssertRead(t assert.TestingT, r io.Reader, b []byte) {
	AssertReadMask(t, r, b, nil)
}

func AssertReadMask(t assert.TestingT, r io.Reader, b []byte, m []byte) {
	if m != nil && len(b) > len(m) {
		panic("mask should longer than data")
	}

	b2 := arrayx.Dup(b)
	b3 := arrayx.Dup(b)

	_, err := io.ReadFull(r, b2)
	assert.NoError(t, err)
	if m != nil {
		for i := 0; i < len(b); i++ {
			mask := m[i] ^ 0xff
			b2[i] &= mask
			b3[i] &= mask
		}
	}
	assert.Equal(t, b3, b2)
}

func AssertWrite(t assert.TestingT, w io.Writer, b []byte) {
	l, err := w.Write(b)
	assert.NoError(t, err)
	assert.EqualValues(t, len(b), l)
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

func AssertForward(t assert.TestingT, r io.Reader, w io.Writer) {
	l := 1024 * 1024
	data := rnd.RandBytes(l)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		AssertRead(t, r, data)
		wg.Done()
	}()
	go func() {
		n, err := io.Copy(w, bytes.NewReader(data))
		assert.EqualValues(t, l, n)
		assert.NoError(t, err)
		wg.Done()
	}()
	wg.Wait()
}

func AssertForward2(t assert.TestingT, n1, n2 io.ReadWriteCloser) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		AssertForward(t, n1, n2)
		wg.Done()
	}()
	go func() {
		AssertForward(t, n2, n1)
		wg.Done()
	}()
	wg.Wait()
}
