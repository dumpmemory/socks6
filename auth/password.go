package auth

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/studentmain/socks6/message"
)

const authIdPassword byte = 2

type passwordAuthenticationData struct {
	Username []byte
	Password []byte
}

// PasswordServerAuthenticationMethod is IANA method 2, check for plaintext user name and password
type PasswordServerAuthenticationMethod struct {
	// Passwords is client password table, key is user name
	Passwords map[string]string
}

func ParsePasswordAuthenticationData(buf []byte) (*passwordAuthenticationData, error) {
	r := bytes.NewReader(buf)
	v, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if v != 1 {
		return nil, message.NewErrVersionMismatch(int(v), nil)
	}
	ulen, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	u := make([]byte, ulen)
	if _, err := io.ReadFull(r, u); err != nil {
		return nil, err
	}

	plen, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	p := make([]byte, plen)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return &passwordAuthenticationData{
		Username: u,
		Password: p,
	}, nil
}

func (p PasswordServerAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	data []byte,
	sac *ServerAuthenticationChannels,
) {
	ad, err := ParsePasswordAuthenticationData(data)
	failResult := ServerAuthenticationResult{
		Success:  false,
		Continue: false,
	}
	if err != nil {
		sac.Result <- failResult
		sac.Err <- err
		return
	}
	expect, ok := p.Passwords[string(ad.Username)]
	failResult.MethodData = []byte{1, 1}
	if !ok {
		sac.Result <- failResult
		sac.Err <- nil
		return
	}
	if expect != string(ad.Password) {
		sac.Result <- failResult
		sac.Err <- nil
		return
	}

	sac.Result <- ServerAuthenticationResult{
		Success:    true,
		Continue:   false,
		MethodData: []byte{1, 0},
	}
	sac.Err <- nil
}
func (p PasswordServerAuthenticationMethod) ID() byte {
	return authIdPassword
}

type PasswordClientAuthenticationMethod struct {
	Username string
	Password string
}

func (p PasswordClientAuthenticationMethod) Authenticate(
	ctx context.Context,
	conn net.Conn,
	cac ClientAuthenticationChannels,
) {
	b := bytes.Buffer{}
	b.WriteByte(1)
	b.WriteByte(byte(len(p.Username)))
	b.Write([]byte(p.Username))
	b.WriteByte(byte(len(p.Password)))
	b.Write([]byte(p.Password))
	cac.Data <- b.Bytes()

	// data is ignored
	rep1 := <-cac.FirstAuthReply
	cac.FinalAuthReply <- rep1
	cac.Error <- nil
}
func (p PasswordClientAuthenticationMethod) ID() byte {
	return authIdPassword
}
