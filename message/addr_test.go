package message_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/message"
)

func TestNewAddr(t *testing.T) {
	tests := []struct {
		in     string
		expect *message.Socks6Addr
		ok     bool
	}{
		{in: "", expect: nil, ok: false},
		{in: "a", expect: nil, ok: false},
		{in: "a:1",
			expect: &message.Socks6Addr{
				AddressType: message.AddressTypeDomainName,
				Address:     []byte{'a'},
				Port:        1,
			},
			ok: true},
		{in: "a:1919810", expect: nil, ok: false},
		{in: "苟:1",
			expect: &message.Socks6Addr{
				AddressType: message.AddressTypeDomainName,
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
			expect: &message.Socks6Addr{
				AddressType: message.AddressTypeIPv4,
				Address:     []byte{127, 0, 0, 1},
				Port:        1,
			},
			ok: true},
		{in: "[fe80:1234::1]:1",
			expect: &message.Socks6Addr{
				AddressType: message.AddressTypeIPv6,
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
		actual, err := message.NewAddr(tt.in)
		if tt.ok {
			assert.Nil(t, err)
			assert.Equal(t, tt.expect, actual)
		} else {
			assert.Error(t, err)
		}
	}

	for _, tt := range tests {
		if !tt.ok {
			assert.Panics(t, func() { message.NewAddrP(tt.in) })
		} else {
			assert.Equal(t, tt.expect, message.NewAddrP(tt.in))
		}
	}
}

func TestAddrString(t *testing.T) {
	tests := []struct {
		in  message.Socks6Addr
		out string
	}{
		{in: message.Socks6Addr{
			AddressType: message.AddressTypeIPv6,
			Address: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
			Port: 1,
		}, out: "[fe80:1234::1]:1"},
		{in: message.Socks6Addr{
			AddressType: message.AddressTypeIPv4,
			Address: []byte{
				127, 0, 0, 1,
			},
			Port: 2,
		}, out: "127.0.0.1:2"},
		{in: message.Socks6Addr{
			AddressType: message.AddressTypeDomainName,
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
		atyp message.AddressType
		bin  []byte
		addr message.Socks6Addr
		out  string
	}{
		{
			atyp: message.AddressTypeIPv6,
			bin: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeIPv6,
				Address: []byte{
					0xfe, 0x80, 0x12, 0x34,
					0, 0, 0, 0,
					0, 0, 0, 0,
					0, 0, 0, 1,
				},
			},
		},
		{
			atyp: message.AddressTypeIPv4,
			bin: []byte{
				127, 0, 0, 1,
			},
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeIPv4,
				Address: []byte{
					127, 0, 0, 1,
				},
			},
		},
		{
			atyp: message.AddressTypeDomainName,
			bin:  append([]byte{16}, []byte("example.com\x00\x00\x00\x00\x00")...),
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeDomainName,
				Address:     []byte("example.com"),
			},
		},
	}
	for _, tt := range tests {
		a := message.Socks6Addr{}
		a.ParseAddress(tt.atyp, tt.bin)
		assert.Equal(t, tt.addr, a)
	}

	b := message.Socks6Addr{}
	ftests := []struct {
		atyp message.AddressType
		addr []byte
		e    error
	}{
		{atyp: message.AddressTypeDomainName, addr: nil, e: message.ErrTooShort{ExpectedLen: 2}},
		{atyp: message.AddressTypeDomainName, addr: []byte{100, 1}, e: message.ErrTooShort{ExpectedLen: 101}},
		{atyp: message.AddressType(9), addr: nil, e: message.ErrAddressTypeNotSupport},
		{atyp: message.AddressTypeIPv4, addr: nil, e: message.ErrTooShort{ExpectedLen: 4}},
		{atyp: message.AddressTypeIPv6, addr: nil, e: message.ErrTooShort{ExpectedLen: 16}},
	}
	for _, tt := range ftests {
		_, e := b.ParseAddress(tt.atyp, tt.addr)
		assert.Error(t, e, tt.e)
	}
}

func TestAddrMarshalAddress(t *testing.T) {
	tests := []struct {
		addr message.Socks6Addr
		bin  []byte
	}{
		{addr: message.Socks6Addr{
			AddressType: message.AddressTypeIPv4,
			Address:     []byte{127, 0, 0, 1},
		}, bin: []byte{127, 0, 0, 1}},
		{addr: message.Socks6Addr{
			AddressType: message.AddressTypeIPv6,
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
		{addr: message.Socks6Addr{
			AddressType: message.AddressTypeDomainName,
			Address:     []byte("aaa"),
		}, bin: []byte{3, 'a', 'a', 'a'}},
		{addr: message.Socks6Addr{
			AddressType: message.AddressTypeDomainName,
			Address:     []byte("aa"),
		}, bin: []byte{3, 'a', 'a', 0}},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.bin, tt.addr.MarshalAddress())
	}
}

func TestAddrParseAddressFrom(t *testing.T) {
	tests := []struct {
		atyp message.AddressType
		bin  []byte
		addr message.Socks6Addr
		out  string
	}{
		{
			atyp: message.AddressTypeIPv6,
			bin: []byte{
				0xfe, 0x80, 0x12, 0x34,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1,
			},
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeIPv6,
				Address: []byte{
					0xfe, 0x80, 0x12, 0x34,
					0, 0, 0, 0,
					0, 0, 0, 0,
					0, 0, 0, 1,
				},
			},
		},
		{
			atyp: message.AddressTypeIPv4,
			bin: []byte{
				127, 0, 0, 1,
			},
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeIPv4,
				Address: []byte{
					127, 0, 0, 1,
				},
			},
		},
		{
			atyp: message.AddressTypeDomainName,
			bin:  append([]byte{16}, []byte("example.com\x00\x00\x00\x00\x00")...),
			addr: message.Socks6Addr{
				AddressType: message.AddressTypeDomainName,
				Address:     []byte("example.com"),
			},
		},
	}
	for _, tt := range tests {
		buf := bytes.NewBuffer(tt.bin)
		a, e := message.ParseAddressFrom(buf, tt.atyp)
		assert.Nil(t, e)
		a.ParseAddress(tt.atyp, tt.bin)
		assert.Equal(t, &tt.addr, a)
	}

	ftests := []struct {
		atyp message.AddressType
		addr []byte
		e    error
	}{
		{atyp: message.AddressTypeDomainName, addr: nil, e: io.EOF},
		{atyp: message.AddressTypeDomainName, addr: []byte{100, 1}, e: io.ErrUnexpectedEOF},
		{atyp: message.AddressType(9), addr: nil, e: message.ErrAddressTypeNotSupport},
		{atyp: message.AddressTypeIPv4, addr: nil, e: io.EOF},
		{atyp: message.AddressTypeIPv6, addr: nil, e: io.EOF},
	}
	for _, tt := range ftests {
		buf := bytes.NewBuffer(tt.addr)
		_, e := message.ParseAddressFrom(buf, tt.atyp)
		assert.ErrorIs(t, e, tt.e)
	}
}
