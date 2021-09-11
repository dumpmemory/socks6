package auth

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/studentmain/socks6/message"
)

type PasswordServerAuthenticationMethod struct {
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
	if err != nil {
		sac.Result <- ServerAuthenticationResult{
			Success:  false,
			Continue: false,
		}
		sac.Err <- err
		return
	}
	expect, ok := p.Passwords[string(ad.Username)]
	if !ok {
		sac.Result <- ServerAuthenticationResult{
			Success:    false,
			Continue:   false,
			OptionData: []byte{1, 1},
		}
		sac.Err <- nil
		return
	}
	if expect != string(ad.Password) {
		sac.Result <- ServerAuthenticationResult{
			Success:    false,
			Continue:   false,
			OptionData: []byte{1, 1},
		}
		sac.Err <- nil
		return
	}
	sac.Result <- ServerAuthenticationResult{
		Success:    true,
		Continue:   false,
		OptionData: []byte{1, 0},
	}
	sac.Err <- nil
}
