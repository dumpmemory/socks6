package auth

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/studentmain/socks6/message"
)

// PasswordServerAuthenticationMethod is IANA method 2, check for plaintext user name and password
type PasswordServerAuthenticationMethod struct {
	// Passwords is client password table, key is user name
	Passwords map[string]string
}

type PasswordAuthenticationData struct {
	Username []byte
	Password []byte
}

func ParsePasswordAuthenticationData(buf []byte) (*PasswordAuthenticationData, error) {
	r := bytes.NewReader(buf)
	v, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if v != 1 {
		return nil, message.ErrVersion{Version: int(v)}
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
	return &PasswordAuthenticationData{
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
