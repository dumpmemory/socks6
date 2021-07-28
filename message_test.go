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

func extractOptions(buf []byte) []socks6.Option {
	o := []socks6.Option{}
	for p := 0; len(buf[p:]) > 0; {
		op := socks6.Option(buf[p:])
		p += int(op.Length())
		o = append(o, op)
	}
	return o
}

func pickOption(o []socks6.Option, kind uint16) socks6.Option {
	for _, v := range o {
		if v.Kind() == kind {
			return v
		}
	}
	return nil
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
