package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

func Test1(t *testing.T) {
	req := socks6.Request{
		CommandCode: 1,
		Endpoint:    socks6.NewAddrP("127.0.0.1:1"),
	}
	assert.Equal(t, []byte{
		6, 1, 0, 0,
		0, 1, 0, 1,
		127, 0, 0, 1,
	}, req.Marshal())

}
