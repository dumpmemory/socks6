package socks6_test

import (
	"testing"

	"github.com/studentmain/socks6"
)

func TestRequest(t *testing.T) {
	req := []byte{
		6, 1, 0, 0,
		0, 80, 0, 1,
		127, 0, 0, 1,
	}
	r := socks6.Request{}
	r.Deserialize(req)
	if r.Endpoint.String() != "127.0.0.1:80" {
		t.Fail()
	}

	req = []byte{
		6, 1, 0, 8,
		0, 80, 0, 3,

		15, 'e', 'x', 'a',
		'm', 'p', 'l', 'e',
		'.', 'c', 'o', 'm',
		0, 0, 0, 0,

		0, 2, 0, 8,
		0, 4, 1, 2,

		1, 2, 3, 4,
	}
	l, e := r.Deserialize(req)
	if e != nil {
		t.Error(e)
	}
	if l != 32 {
		t.Fail()
	}
	if r.Endpoint.String() != "example.com:80" {
		t.Fail()
	}
	if !byteArrayEq(r.InitialData, []byte{1, 2, 3, 4}) {
		t.Fail()
	}
}

func TestEndpoint(t *testing.T) {
	ep := socks6.Endpoint{
		AddressType: socks6.AF_DomainName,
		Port:        80,
		NetString:   "tcp",
	}
	l, e := ep.DeserializeAddress([]byte("\u000eexample.com\u0000\u0000\u0000"))
	if e != nil {
		t.Error(e)
	}
	if len(ep.Address) != 11 || l != 15 {
		t.Fail()
	}
	if ep.Network() != "tcp" {
		t.Error("wtf")
	}
}
