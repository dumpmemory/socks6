package socks6

import (
	"io"
	"sort"
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

func ReadMessageFrom(msg Message, r io.Reader) (int, error) {
	buf := []byte{}
	p := 0
	for i := 0; i < 64; i++ {
		l, err := msg.Deserialize(buf)

		if err == nil {
			return l, err
		}
		if ets, ok := err.(ErrTooShort); ok {
			nRead := ets.ExpectedLen - p
			// todo memory pool
			buf = append(buf, make([]byte, nRead)...)
			nActual, err := io.ReadFull(r, buf[p:ets.ExpectedLen])
			if nRead != nActual {
				return 0, io.ErrNoProgress
			}
			if err != nil {
				return 0, err
			}
			p = ets.ExpectedLen
		} else {
			return 0, err
		}
	}
	return p, nil
}

func WriteMessage(msg Message) ([]byte, error) {
	buf := []byte{}
	for i := 0; i < 64; i++ {
		l, err := msg.Serialize(buf)
		if err == nil {
			return buf[:l], err
		}
		if ets, ok := err.(ErrTooShort); ok {
			buf = make([]byte, ets.ExpectedLen)
		} else {
			return nil, err
		}
	}
	return nil, ErrFormat
}

func WriteMessageTo(msg Message, w io.Writer) error {
	b, err := WriteMessage(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func dup(i []byte) []byte {
	o := make([]byte, len(i))
	copy(o, i)
	return o
}

func PaddedLen(l int, align int) int {
	return (l + align - 1) / align * align
}

func SortByte(b []byte) {
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
}
