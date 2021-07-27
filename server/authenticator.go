package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/studentmain/socks6"
	"golang.org/x/crypto/sha3"
)

type AuthenticationMethodSelector struct {
	idOrder    []byte
	idMap      map[byte]AuthenticationMethod
	methodToId map[string]byte
}

func (a *AuthenticationMethodSelector) AddMethod(m AuthenticationMethod) {
	id, name := m.ID()
	a.idMap[id] = m
	a.methodToId[name] = id
}
func (a *AuthenticationMethodSelector) EnableMethod(m []string) {
	a.idOrder = make([]byte, len(m))
	for i := 0; i < len(m); i++ {
		id := a.methodToId[m[i]]
		a.idOrder[i] = id
	}
}
func (a *AuthenticationMethodSelector) Authenticate(req socks6.Request) AuthenticationResult {
	m := append(req.Methods, 0)
	// todo: uniq
	ia := byte(0)
	for _, id := range a.idOrder {
		if bytes.Contains(m, []byte{id}) {
			method := a.idMap[id]
			v := req.MethodData[id]
			result := method.Authenticate(v)

			if result.Success {
				result.SelectedMethod = id
				return result
			}
			ok := method.InteractiveAuthenticate(v)
			if ok && ia != 0 {
				ia = id
			}
		}
	}
	return AuthenticationResult{
		Success:        false,
		SelectedMethod: ia,
	}
}
func (a *AuthenticationMethodSelector) AuthenticationProtocol(
	req socks6.Request,
	methodId byte,
	conn io.ReadWriteCloser,
) AuthenticationResult {
	data := req.MethodData[methodId]
	method := a.idMap[methodId]
	return method.AuthenticationProtocol(data, conn)
}

// client's name, for logging etc
type ClientID string

type AuthenticationMethod interface {
	ID() (byte, string)
	Authenticate(data []byte) AuthenticationResult
	InteractiveAuthenticate(data []byte) bool
	AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) AuthenticationResult
}
type NoneAuthentication struct {
}

func (n NoneAuthentication) ID() (byte, string) {
	return socks6.AuthenticationMethodNone, "none"
}
func (n NoneAuthentication) Authenticate(data []byte) AuthenticationResult {
	return AuthenticationResult{Success: true}
}
func (n NoneAuthentication) InteractiveAuthenticate(data []byte) bool {
	return false
}
func (n NoneAuthentication) AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) AuthenticationResult {
	return AuthenticationResult{Success: true}
}

type UsernamePasswordAuthentication struct {
}

func (n UsernamePasswordAuthentication) ID() (byte, string) {
	return 2, "username-password"
}
func (n UsernamePasswordAuthentication) Authenticate(data []byte) AuthenticationResult {
	// TODO
	return AuthenticationResult{Success: true}
}
func (n UsernamePasswordAuthentication) InteractiveAuthenticate(data []byte) bool {
	return false
}
func (n UsernamePasswordAuthentication) AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) AuthenticationResult {
	return n.Authenticate(data)
}

type DefaultAuthenticator struct {
	DisableSession bool
	DisableToken   bool
	MethodSelector AuthenticationMethodSelector
	sessions       map[uint64]ClientID // key is hashed sessionid
}

// todo: authenticate return this one instead
type AuthenticationResult struct {
	Success        bool
	SelectedMethod byte
	ClientID       ClientID
	SessionID      []byte
}

const sessionLength = 8

func (d DefaultAuthenticator) Authenticate(req socks6.Request) (AuthenticationResult, socks6.AuthenticationReply) {
	if !d.DisableSession && req.SessionID != nil {
		h := sha3.NewShake128()
		h.Write(req.SessionID)
		b := make([]byte, 8)
		h.Read(b)
		sid64 := binary.BigEndian.Uint64(b)
		if req.RequestTeardown {
			delete(d.sessions, sid64)
		}
		if d.sessions[sid64] == "" || req.RequestTeardown {
			// fail fast
			sar := socks6.AuthenticationReply{
				Type:         socks6.AuthenticationReplyFail,
				InSession:    true,
				SessionValid: false,
			}
			return AuthenticationResult{
				Success: false,
			}, sar
		}
		// TODO:token
	}

	msar := d.MethodSelector.Authenticate(req)
	if !msar.Success {
		if msar.SelectedMethod == 0 {
			return msar, socks6.AuthenticationReply{
				Type: socks6.AuthenticationReplyFail,
			}
		} else {
			return msar, socks6.AuthenticationReply{
				Type:           socks6.AuthenticationReplyFail,
				SelectedMethod: msar.SelectedMethod,
			}
		}
	}

	sar := socks6.AuthenticationReply{
		Type:           socks6.AuthenticationReplySuccess,
		SelectedMethod: msar.SelectedMethod,
	}

	if !d.DisableSession && req.RequestSession {
		msar.SessionID = make([]byte, sessionLength)
		rand.Read(msar.SessionID)
	} else {
		msar.SessionID = req.SessionID
	}
	return msar, sar
}
