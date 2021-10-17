package auth

import (
	"context"
	"encoding/base64"
	"net"
	"sync"
	"time"

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
	ContinueAuthenticate(sac *ServerAuthenticationChannels, req message.Request) (*ServerAuthenticationResult, error)
	SessionConnClose(id []byte)
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

type DefaultServerAuthenticator struct {
	Methods map[byte]ServerAuthenticationMethod

	DisableSession bool
	DisableToken   bool

	sessions sync.Map // map[base64_rawstd(id)]*session
}

func (d *DefaultServerAuthenticator) Authenticate(
	ctx context.Context,
	conn net.Conn,
	req message.Request,
) (
	*ServerAuthenticationResult,
	*ServerAuthenticationChannels,
) {
	if sessionData, useSession := req.Options.GetData(message.OptionKindSessionID); useSession {
		sid := sessionData.(message.SessionIDOptionData).ID
		return d.sessionCheck(req, sid), NewServerAuthenticationChannels()
	}
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
	r, c := d.pickMethod(ctx, conn, authData, order)
	return d.tryStartSesstion(r, req), c
}

func (d *DefaultServerAuthenticator) ContinueAuthenticate(sac *ServerAuthenticationChannels, req message.Request) (*ServerAuthenticationResult, error) {
	sac.Continue <- true
	err := <-sac.Err
	if err != nil {
		return nil, err
	}
	result := <-sac.Result
	return d.tryStartSesstion(&result, req), nil
}

func (d *DefaultServerAuthenticator) pickMethod(
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

func (d *DefaultServerAuthenticator) AddMethod(method ServerAuthenticationMethod) {
	d.Methods[method.ID()] = method
}

func (d *DefaultServerAuthenticator) sessionCheck(
	req message.Request,
	sid []byte,
) *ServerAuthenticationResult {
	sessionInvalid := ServerAuthenticationResult{
		Success:  false,
		Continue: false,

		AdditionalOptions: []message.Option{
			{Kind: message.OptionKindSessionInvalid, Data: message.SessionInvalidOptionData{}},
		},
	}
	if d.DisableSession {
		return &sessionInvalid
	}
	sk := base64.RawStdEncoding.EncodeToString(sid)
	var session *serverSession
	if isession, ok := d.sessions.Load(sk); ok {
		session = isession.(*serverSession)
	} else {
		// mismatch session
		return &sessionInvalid
	}

	// requested teardown
	if _, teardown := req.Options.GetData(message.OptionKindSessionTeardown); teardown {
		d.sessions.Delete(sk)
		return &sessionInvalid
	}
	// session success
	sar := ServerAuthenticationResult{
		Continue: false,

		SessionID: sid,
		AdditionalOptions: []message.Option{
			{Kind: message.OptionKindSessionOK, Data: message.SessionOKOptionData{}},
		},
	}
	// token request
	windowRequestData, requested := req.Options.GetData(message.OptionKindTokenRequest)
	windowRequest := uint32(0)
	// requested window
	if requested && !d.DisableToken {
		windowRequest = windowRequestData.(message.TokenRequestOptionData).WindowSize
		// allocate when no window
		if session.window.Length() == 0 {
			if windowRequest > 2048 {
				windowRequest = 2048
			}
			alloc, base, size := session.allocateWindow(uint32(windowRequest))
			if alloc {
				sar.AdditionalOptions = append(sar.AdditionalOptions, message.Option{
					Kind: message.OptionKindIdempotenceWindow,
					Data: message.IdempotenceWindowOptionData{
						WindowBase: base,
						WindowSize: size,
					},
				})
			}
		}
	}

	// token check
	tokenData, spend := req.Options.GetData(message.OptionKindIdempotenceExpenditure)
	if !spend {
		// not used
		sar.Success = true
		return &sar
	}
	// spending token
	if d.DisableToken {
		sar.Success = false
		sar.AdditionalOptions = append(sar.AdditionalOptions, message.Option{
			Kind: message.OptionKindIdempotenceRejected,
			Data: message.IdempotenceRejectedOptionData{},
		})
		return &sar
	}

	token := tokenData.(message.IdempotenceExpenditureOptionData).Token
	if !session.checkToken(token) {
		// token fail
		sar.Success = false
		sar.AdditionalOptions = append(sar.AdditionalOptions, message.Option{
			Kind: message.OptionKindIdempotenceRejected,
			Data: message.IdempotenceRejectedOptionData{},
		})
		return &sar
	}

	// token success
	sar.Success = true
	sar.AdditionalOptions = append(sar.AdditionalOptions, message.Option{
		Kind: message.OptionKindIdempotenceAccepted,
		Data: message.IdempotenceAcceptedOptionData{},
	})

	// allocate when necessary/requested
	alloc, base, size := session.allocateWindow(uint32(windowRequest))
	if alloc {
		sar.AdditionalOptions = append(sar.AdditionalOptions, message.Option{
			Kind: message.OptionKindIdempotenceWindow,
			Data: message.IdempotenceWindowOptionData{
				WindowBase: base,
				WindowSize: size,
			},
		})
	}

	return &sar
}

func (d *DefaultServerAuthenticator) tryStartSesstion(
	result *ServerAuthenticationResult,
	req message.Request,
) *ServerAuthenticationResult {
	if !result.Success {
		return result
	}
	if _, requested := req.Options.GetData(message.OptionKindSessionRequest); !requested {
		return result
	}
	s := newServerSession(8)
	result.AdditionalOptions = append(result.AdditionalOptions, message.Option{
		Kind: message.OptionKindSessionID,
		Data: message.SessionIDOptionData{ID: s.id},
	})
	result.AdditionalOptions = append(result.AdditionalOptions, message.Option{
		Kind: message.OptionKindSessionOK,
		Data: message.SessionOKOptionData{},
	})
	result.SessionID = s.id

	if tokenData, requestToken := req.Options.GetData(message.OptionKindTokenRequest); requestToken {
		// token
		windowRequest := tokenData.(message.TokenRequestOptionData).WindowSize
		alloc, base, size := s.allocateWindow(uint32(windowRequest))
		if alloc {
			result.AdditionalOptions = append(result.AdditionalOptions, message.Option{
				Kind: message.OptionKindIdempotenceWindow,
				Data: message.IdempotenceWindowOptionData{
					WindowBase: base,
					WindowSize: size,
				},
			})
		}
	}
	return result
}

func (d *DefaultServerAuthenticator) SessionConnClose(id []byte) {
	sk := base64.RawStdEncoding.EncodeToString(id)
	var session *serverSession
	if isession, ok := d.sessions.Load(sk); ok {
		session = isession.(*serverSession)
	} else {
		return
	}
	session.connCount--
	if session.connCount <= 0 {
		go func() {
			<-time.After(5 * time.Minute)
			if session.connCount <= 0 {
				d.sessions.Delete(sk)
			}
		}()
	}
}
