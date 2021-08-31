package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/message"
)

func Test1(t *testing.T) {
	req := message.Request{
		CommandCode: 1,
		Endpoint:    message.NewAddrP("127.0.0.1:1"),
	}
	assert.Equal(t, []byte{
		6, 1, 0, 0,
		0, 1, 0, 1,
		127, 0, 0, 1,
	}, req.Marshal())

}
