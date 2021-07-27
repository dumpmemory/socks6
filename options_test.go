package socks6_test

import (
	"testing"

	"github.com/studentmain/socks6"
)

func byteArrayEq(a, b []byte) bool {
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

func TestOption(t *testing.T) {
	arr := make([]byte, 128)
	o, e := socks6.OptionCtor(arr, 1, 12)
	if e != nil {
		t.Error(e)
	}
	if o.Kind() != 1 {
		t.Fail()
	}
	if o.Length() != 12 {
		t.Fail()
	}
	if len(o) != 12 {
		t.Fail()
	}
	if !byteArrayEq(o, []byte{0, 1, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fail()
	}
	if !byteArrayEq(o.OptionData(), []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fail()
	}

	_, e = socks6.OptionCtor(arr[:3], 0, 12)
	if e == nil {
		t.Fail()
	}
}
