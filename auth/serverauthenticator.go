package auth

import (
	"context"
	"net"

	"github.com/studentmain/socks6/message"
)

type ServerAuthenticator interface {
	Authenticate(
		ctx context.Context,
		conn net.Conn,
		req message.Request,
	) (
		*ServerAuthenticationResult,
		*ServerAuthenticationChannels,
	)
	ContinueAuthenticate(sac *ServerAuthenticationChannels) (*ServerAuthenticationResult, error)
}

type ServerAuthenticationResult struct {
	Success        bool
	SelectedMethod byte
	Continue       bool

	SessionID         []byte
	MethodData        []byte
	AdditionalOptions []message.Option

	ClientName string
}

type NullServerAuthenticator struct{}

func (n *NullServerAuthenticator) Authenticate(
	ctx context.Context,
	conn net.Conn,
	req message.Request,
) (
	*ServerAuthenticationResult,
	chan ServerAuthenticationResult,
	chan bool,
) {
	return &ServerAuthenticationResult{
		Success: true,
	}, nil, nil
}

type DefaultServerAuthenticator struct {
	Methods map[byte]ServerAuthenticationMethod
}

func (d DefaultServerAuthenticator) Authenticate(
	ctx context.Context,
	conn net.Conn,
	req message.Request,
) (
	*ServerAuthenticationResult,
	*ServerAuthenticationChannels,
) {
	order := []byte{0}
	if orderData, ok := req.Options.GetData(message.OptionKindAuthenticationMethodAdvertisement); ok {
		order = append(order, orderData.(message.AuthenticationMethodAdvertisementOptionData).Methods...)
	}
	authData := map[byte][]byte{}
	ads := req.Options.GetKind(message.OptionKindAuthenticationData)
	for _, v := range ads {
		data := v.Data.(message.AuthenticationDataOptionData)
		authData[data.Method] = data.Data
	}
	return d.pickMethod(ctx, conn, authData, order)
}

func (d DefaultServerAuthenticator) ContinueAuthenticate(sac *ServerAuthenticationChannels) (*ServerAuthenticationResult, error) {
	sac.Continue <- true
	err := <-sac.Err
	if err != nil {
		return nil, err
	}
	result := <-sac.Result
	return &result, nil
}

func (d DefaultServerAuthenticator) pickMethod(
	ctx context.Context,
	conn net.Conn,
	authData map[byte][]byte,
	order []byte,
) (
	*ServerAuthenticationResult,
	*ServerAuthenticationChannels,
) {
	for _, m := range order {
		data := authData[m]
		sac := NewServerAuthenticationChannels()
		method, support := d.Methods[m]
		if !support {
			continue
		}
		go method.Authenticate(ctx, conn, data, sac)
		result1 := <-sac.Result
		if result1.Success {
			// success at phase 1
			sac.Continue <- false
			return &ServerAuthenticationResult{
				Success:        true,
				SelectedMethod: m,
				ClientName:     result1.ClientName,
				MethodData:     result1.MethodData,
				Continue:       false,
			}, sac
		} else if result1.Continue {
			// can get into phase 2
			return &ServerAuthenticationResult{
				Success:        false,
				SelectedMethod: m,
				ClientName:     result1.ClientName,
				MethodData:     result1.MethodData,
				Continue:       true,
			}, sac
		} else {
			// fail and cant continue
			sac.Continue <- false
		}
	}
	return &ServerAuthenticationResult{
		Success:        false,
		SelectedMethod: 0xff,
		Continue:       false,
	}, nil
}

func (d *DefaultServerAuthenticator) AddMethod(id byte, method ServerAuthenticationMethod) {
	d.Methods[id] = method
}
