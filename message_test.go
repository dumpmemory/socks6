package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

func TestEndpoint_DeserializeAddress(t *testing.T) {
	ep := socks6.Endpoint{}

	_, err := ep.DeserializeAddress([]byte{})
	assert.Equal(t, socks6.ErrEnumValue, err)

	ep.AddressType = socks6.AddressTypeIPv4
	l, err := ep.DeserializeAddress([]byte{1, 2, 3, 4})
	assert.Nil(t, err)
	assert.Equal(t, 4, l)
	assert.Equal(t, "1.2.3.4:0", ep.String())
	_, err = ep.DeserializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)

	ep.AddressType = socks6.AddressTypeDomainName
	l, err = ep.DeserializeAddress([]byte("\u000eexample.com\x00\x00\x00"))
	assert.Nil(t, err)
	assert.Equal(t, 15, l)
	assert.Equal(t, []byte("example.com"), ep.Address)
	assert.Equal(t, "example.com:0", ep.String())
	_, err = ep.DeserializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 2}, err)
	_, err = ep.DeserializeAddress([]byte{31, 0, 0})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 32}, err)
	l, err = ep.DeserializeAddress([]byte{3, 'a', 'b', 'c'})
	assert.Nil(t, err)
	assert.Equal(t, 4, l)
	assert.Equal(t, []byte("abc"), ep.Address)
	assert.Equal(t, "abc:0", ep.String())

	ep.AddressType = socks6.AddressTypeIPv6
	l, err = ep.DeserializeAddress([]byte{1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	assert.Nil(t, err)
	assert.Equal(t, 16, l)
	assert.Equal(t, "[100:0:7f00::1]:0", ep.String())
	_, err = ep.DeserializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 16}, err)

}

func TestEndpoint_String(t *testing.T) {
	ep := socks6.Endpoint{}
	ep.Port = 9961

	ep.AddressType = socks6.AddressTypeIPv4
	ep.Address = []byte{1, 2, 3, 4}
	assert.Equal(t, "1.2.3.4:9961", ep.String())

	ep.AddressType = socks6.AddressTypeDomainName
	ep.Address = []byte("example.com")
	assert.Equal(t, "example.com:9961", ep.String())

	ep.AddressType = socks6.AddressTypeIPv6
	ep.Address = []byte{1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	assert.Equal(t, "[100:0:7f00::1]:9961", ep.String())
}

func TestEndpoint_SerializeAddress(t *testing.T) {
	ep := socks6.Endpoint{}
	buf := make([]byte, 64)
	_, err := ep.SerializeAddress(buf)
	assert.Equal(t, socks6.ErrEnumValue, err)

	ep.AddressType = socks6.AddressTypeIPv4
	ep.Address = []byte{1, 2, 3, 4}
	l, err := ep.SerializeAddress(buf)
	assert.Nil(t, err)
	assert.Equal(t, 4, l)
	assert.Equal(t, []byte{1, 2, 3, 4}, buf[:l])
	_, err = ep.SerializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 4}, err)

	ep.AddressType = socks6.AddressTypeDomainName
	ep.Address = []byte("a.example.com")
	l, err = ep.SerializeAddress(buf)
	assert.Nil(t, err)
	assert.Equal(t, 16, l)
	assert.Equal(t, []byte("\u000fa.example.com\x00\x00"), buf[:l])
	_, err = ep.SerializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 16}, err)

	ep.AddressType = socks6.AddressTypeIPv6
	ep.Address = []byte{1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	l, err = ep.SerializeAddress(buf)
	assert.Nil(t, err)
	assert.Equal(t, 16, l)
	assert.Equal(t, []byte{1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, buf[:l])
	_, err = ep.SerializeAddress([]byte{})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 16}, err)
}

func TestNewEndpoint(t *testing.T) {
	ep := socks6.Endpoint{}

	ep = socks6.NewEndpoint("1.2.3.4:9961")
	assert.Equal(t, socks6.Endpoint{
		AddressType: socks6.AddressTypeIPv4,
		Address:     []byte{1, 2, 3, 4},
		Port:        9961,
	}, ep)

	ep = socks6.NewEndpoint("a.example.com:9961")
	assert.Equal(t, socks6.Endpoint{
		AddressType: socks6.AddressTypeDomainName,
		Address:     []byte("a.example.com"),
		Port:        9961,
	}, ep)

	ep = socks6.NewEndpoint("[100:0:7f00::1]:9961")
	assert.Equal(t, socks6.Endpoint{
		AddressType: socks6.AddressTypeIPv6,
		Address:     []byte{1, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:        9961,
	}, ep)

	ep = socks6.NewEndpoint("苟利国家生死以:岂因祸福避趋之")
	assert.Equal(t, socks6.Endpoint{}, ep)
	ep = socks6.NewEndpoint("苟[利国家生死以:岂因祸福避趋之")
	assert.Equal(t, socks6.Endpoint{}, ep)
}

func TestEndpoint_Network(t *testing.T) {
	ep := socks6.Endpoint{}
	assert.Equal(t, "", ep.Network())
	ep.Net = "tcp"
	assert.Equal(t, "tcp", ep.Network())
}

func TestRequest_Deserialize(t *testing.T) {
	r := socks6.Request{}

	l, err := r.Deserialize([]byte{
		6, 0, 0, 0,
		0, 80, 0, 3,
		11, 'e', 'x', 'a',
		'm', 'p', 'l', 'e',
		'.', 'c', 'o', 'm',
		1, 2, 3, 4,
	})
	assert.Nil(t, err)
	assert.Equal(t, 20, l)
	assert.Equal(t, socks6.Request{
		CommandCode: socks6.CommandNoop,
		Endpoint:    socks6.NewEndpoint("example.com:80"),
		MethodData:  map[byte][]byte{},
	}, r)

	_, err = r.Deserialize(nil)
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 1}, err)
	_, err = r.Deserialize([]byte{6})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 10}, err)
	_, err = r.Deserialize([]byte{5, 1, 0})
	assert.Equal(t, socks6.ErrVersion, err)
	_, err = r.Deserialize([]byte{
		6, 0, 0, 0,
		0, 80, 0, 1,
		127, 0, 0,
	})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 12}, err)
	_, err = r.Deserialize([]byte{
		6, 0, 0, 8,
		0, 80, 0, 1,
		127, 0, 0, 1,
	})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 20}, err)
	_, err = r.Deserialize([]byte{
		6, 0, 0, 8,
		0, 80, 0, 1,
		127, 0, 0, 1,
		0, 2, 0, 8, 0, 64, 1, 0,
	})
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 84}, err)
	_, err = r.Deserialize([]byte{
		6, 0, 0, 8,
		0, 80, 0, 1,
		127, 0, 0, 1,
		0, 0, 0, 100, 0, 0, 0, 0,
	})
	assert.Equal(t, socks6.ErrFormat, err)

	r = socks6.Request{}
	l, err = r.Deserialize([]byte{
		6, 0, 0, 8, 0, 80, 0, 1, 127, 0, 0, 1,
		0, 2, 0, 8, 0, 4, 1, 0,
		1, 2, 3, 4,
		5, 6, 7, 8,
	})
	assert.Nil(t, err)
	assert.Equal(t, 24, l)
	assert.Equal(t, socks6.Request{
		CommandCode: socks6.CommandNoop,
		Endpoint:    socks6.NewEndpoint("127.0.0.1:80"),
		MethodData:  map[byte][]byte{},
		Methods:     []byte{1},
		InitialData: []byte{1, 2, 3, 4},
	}, r)

	r = socks6.Request{}
	l, err = r.Deserialize([]byte{
		6, 0, 0, 72, 0, 80, 0, 1, 127, 0, 0, 1,
		0, 1, 0, 8, 0b11_000001, 1, 3, 0,
		0, 1, 0, 8, 0b01_000001, 2, 2, 0,
		0, 1, 0, 8, 0b01_000001, 3, 3, 0,
		0, 1, 0, 8, 0b01_000001, 4, 1, 0,
		0, 1, 0, 8, 0b01_000100, 1, 2, 0,
		0, 1, 0, 8, 0b01_000100, 2, 1, 0,
		0, 1, 0, 8, 0b01_000100, 3, 2, 0,
		0, 1, 0, 8, 0b01_000101, 1, 2, 0,
		0, 1, 0, 8, 0b01_000101, 2, 3, 1,
	})
	assert.Nil(t, err)
	assert.Equal(t, 84, l)
	p3 := byte(3)
	p512 := uint16(512)
	pf := false
	pt := true
	assert.Equal(t, socks6.Request{
		CommandCode: socks6.CommandNoop,
		Endpoint:    socks6.NewEndpoint("127.0.0.1:80"),
		MethodData:  map[byte][]byte{},
		ClientLegStackOption: socks6.StackOptionData{
			TOS:          &p3,
			HappyEyeball: &pt,
			TTL:          &p3,
			DF:           &pf,

			TFO:     &p512,
			MPTCP:   &pf,
			Backlog: &p512,

			UDPError: &pt,
			Parity:   &p3,
			Reserve:  &pt,
		},
		RemoteLegStackOption: socks6.StackOptionData{
			TOS: &p3,
		},
	}, r)

	r = socks6.Request{}
	l, err = r.Deserialize([]byte{
		6, 0, 0, 56, 0, 80, 0, 1, 127, 0, 0, 1,
		0, 2, 0, 8, 0, 0, 1, 0,
		0, 4, 0, 12, 1, 1, 2, 3, 4, 5, 6, 7,
		0, 5, 0, 4,
		0, 6, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8,
		0, 10, 0, 4,
		0, 11, 0, 8, 0, 0, 1, 0,
		0, 13, 0, 8, 0, 0, 1, 0,
		5, 6, 7, 8,
	})
	assert.Nil(t, err)
	assert.Equal(t, 68, l)
	assert.Equal(t, socks6.Request{
		CommandCode:     socks6.CommandNoop,
		Endpoint:        socks6.NewEndpoint("127.0.0.1:80"),
		MethodData:      map[byte][]byte{1: {1, 2, 3, 4, 5, 6, 7}},
		Methods:         []byte{1},
		RequestSession:  true,
		SessionID:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		RequestTeardown: true,
		RequestToken:    256,
		UseToken:        true,
		TokenToSpend:    256,
	}, r)
}

func TestRequest_Serialize(t *testing.T) {
	r := socks6.Request{
		CommandCode: 1,
		Endpoint:    socks6.NewEndpoint("1.2.3.4:9961"),
		MethodData:  map[byte][]byte{},
	}
	buf := make([]byte, 8+0xff+1+0xffff+0xffff)
	l, err := r.Serialize(buf)
	assert.Nil(t, err)
	assert.Equal(t, 12, l)
	assert.Equal(t, []byte{6, 1, 0, 0, 0x26, 0xe9, 0, 1, 1, 2, 3, 4}, buf[:l])
	_, err = r.Serialize(buf[:0])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 10}, err)
	_, err = r.Serialize(buf[:11])
	assert.Equal(t, socks6.ErrTooShort{ExpectedLen: 12}, err)

	r.Methods = []byte{0xfe}
	r.MethodData[0xfe] = []byte{1, 2, 3, 4}

	r.SessionID = []byte{2, 3, 4, 5}
	r.RequestTeardown = true
	_, err = r.Serialize(buf)
	assert.Nil(t, err)

	r.SessionID = nil
	r.RequestTeardown = false
	r.RequestSession = true
	r.RequestToken = 1024
	_, err = r.Serialize(buf)
	assert.Nil(t, err)

	r.RequestToken = 0
	r.SessionID = []byte{2, 3, 4, 5}
	r.UseToken = true
	r.TokenToSpend = 19260817
	_, err = r.Serialize(buf)
	assert.Nil(t, err)

	// todo validate wireformat
	// todo deal with the advanced error handling
}

// todo stackoptiondata test

func TestAuthenticationReply_Deserialize(t *testing.T) {
	a := socks6.AuthenticationReply{}

	l, err := a.Deserialize([]byte{6, 1, 0, 0, 1, 2, 3, 4})
	assert.Nil(t, err)
	assert.Equal(t, 4, l)
	assert.Equal(t, socks6.AuthenticationReply{
		Type: socks6.AuthenticationReplyFail,
	}, a)
}
