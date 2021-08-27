package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

func TestNewAddr(t *testing.T) {
	tests := []struct {
		in     string
		expect *socks6.Addr
		ok     bool
	}{
		{in: "", expect: nil, ok: false},
		{in: "a", expect: nil, ok: false},
		{in: "a:1",
			expect: &socks6.Addr{
				AddressType: socks6.AddressTypeDomainName,
				Address:     []byte{'a'},
				Port:        1,
			},
			ok: true},
		{in: "a:1919810", expect: nil, ok: false},
		{in: "苟:1",
			expect: &socks6.Addr{
				AddressType: socks6.AddressTypeDomainName,
				Address:     []byte("xn--ui1a"),
				Port:        1,
			},
			ok: true},
		{in: "Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf" +
			"Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf" +
			"Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf" +
			"Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf" +
			"Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf" +
			":1", expect: nil, ok: false},
		{in: "127.0.0.1:1",
			expect: &socks6.Addr{
				AddressType: socks6.AddressTypeIPv4,
				Address:     []byte{127, 0, 0, 1},
				Port:        1,
			},
			ok: true},
		{in: "[fe80:1234::1]:1",
			expect: &socks6.Addr{
				AddressType: socks6.AddressTypeIPv6,
				Address: []byte{
					0xfe, 0x80, 0x12, 0x34,
					0, 0, 0, 0,
					0, 0, 0, 0,
					0, 0, 0, 1,
				},
				Port: 1,
			},
			ok: true},
	}
	for _, tt := range tests {
		actual, err := socks6.NewAddr(tt.in)
		if tt.ok {
			assert.Nil(t, err)
			assert.Equal(t, tt.expect, actual)
		} else {
			assert.Error(t, err)
		}
	}

	for _, tt := range tests {
		if !tt.ok {
			assert.Panics(t, func() { socks6.NewAddrP(tt.in) })
		} else {
			assert.Equal(t, tt.expect, socks6.NewAddrP(tt.in))
		}
	}
}

func TestAddrString(t *testing.T) {
	tests := []struct {
		in  socks6.Addr
		out string
	}{
		{in: socks6.Addr{
			AddressType: socks6.AddressTypeIPv6,
			Address: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
			Port: 1,
		}, out: "[fe80:1234::1]:1"},
		{in: socks6.Addr{
			AddressType: socks6.AddressTypeIPv4,
			Address: []byte{
				127, 0, 0, 1,
			},
			Port: 2,
		}, out: "127.0.0.1:2"},
		{in: socks6.Addr{
			AddressType: socks6.AddressTypeDomainName,
			Address:     []byte("example.com"),
			Port:        3,
		}, out: "example.com:3"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.out, tt.in.String())
	}
}

func TestAddrParseAddress(t *testing.T) {
	tests := []struct {
		atyp socks6.AddressType
		bin  []byte
		addr socks6.Addr
		out  string
	}{
		{
			atyp: socks6.AddressTypeIPv6,
			bin: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
			addr: socks6.Addr{
				AddressType: socks6.AddressTypeIPv6,
				Address: []byte{
					0xfe, 0x80, 0x12, 0x34,
					0, 0, 0, 0,
					0, 0, 0, 0,
					0, 0, 0, 1,
				},
			},
		},
		{
			atyp: socks6.AddressTypeIPv4,
			bin: []byte{
				127, 0, 0, 1,
			},
			addr: socks6.Addr{
				AddressType: socks6.AddressTypeIPv4,
				Address: []byte{
					127, 0, 0, 1,
				},
			},
		},
		{
			atyp: socks6.AddressTypeDomainName,
			bin:  append([]byte{16}, []byte("example.com\x00\x00\x00\x00\x00")...),
			addr: socks6.Addr{
				AddressType: socks6.AddressTypeDomainName,
				Address:     []byte("example.com"),
			},
		},
	}
	for _, tt := range tests {
		a := socks6.Addr{}
		a.ParseAddress(tt.atyp, tt.bin)
		assert.Equal(t, tt.addr, a)
	}

	b := socks6.Addr{}
	ftests := []struct {
		atyp socks6.AddressType
		addr []byte
		e    error
	}{
		{atyp: socks6.AddressTypeDomainName, addr: nil, e: socks6.ErrTooShort{ExpectedLen: 2}},
		{atyp: socks6.AddressTypeDomainName, addr: []byte{100, 1}, e: socks6.ErrTooShort{ExpectedLen: 101}},
		{atyp: socks6.AddressType(9), addr: nil, e: socks6.ErrAddressTypeNotSupport},
		{atyp: socks6.AddressTypeIPv4, addr: nil, e: socks6.ErrTooShort{ExpectedLen: 4}},
		{atyp: socks6.AddressTypeIPv6, addr: nil, e: socks6.ErrTooShort{ExpectedLen: 16}},
	}
	for _, tt := range ftests {
		_, e := b.ParseAddress(tt.atyp, tt.addr)
		assert.Error(t, e, tt.e)
	}
}

func TestAddrMarshalAddress(t *testing.T) {
	tests := []struct {
		addr socks6.Addr
		bin  []byte
	}{
		{addr: socks6.Addr{
			AddressType: socks6.AddressTypeIPv4,
			Address:     []byte{127, 0, 0, 1},
		}, bin: []byte{127, 0, 0, 1}},
		{addr: socks6.Addr{
			AddressType: socks6.AddressTypeIPv6,
			Address: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
		}, bin: []byte{
			0xfe, 0x80, 0x12, 0x34,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 1,
		}},
		{addr: socks6.Addr{
			AddressType: socks6.AddressTypeDomainName,
			Address:     []byte("aaa"),
		}, bin: []byte{3, 'a', 'a', 'a'}},
		{addr: socks6.Addr{
			AddressType: socks6.AddressTypeDomainName,
			Address:     []byte("aa"),
		}, bin: []byte{3, 'a', 'a', 0}},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.bin, tt.addr.MarshalAddress())
	}
}
