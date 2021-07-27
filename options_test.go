package socks6_test

import (
	"testing"

	"github.com/studentmain/socks6"
)

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
	if !socks6.ByteArrayEqual(o, []byte{0, 1, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fail()
	}
	if !socks6.ByteArrayEqual(o.OptionData(), []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fail()
	}

	_, e = socks6.OptionCtor(arr[:3], 0, 12)
	if e == nil {
		t.Fail()
	}
}
