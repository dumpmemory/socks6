package server

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/studentmain/socks6"
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
func (a *AuthenticationMethodSelector) Authenticate(req socks6.Request) (bool, byte, ClientID) {
	m := append(req.Methods, 0)
	// todo: uniq
	ia := byte(0)
	for _, id := range a.idOrder {
		if bytes.Contains(m, []byte{id}) {
			method := a.idMap[id]
			v := req.MethodData[id]
			ok, cid := method.Authenticate(v)
			if ok {
				return ok, id, cid
			}
			ok = method.InteractiveAuthenticate(v)
			if ok && ia != 0 {
				ia = id
			}
		}
	}
	return false, ia, ""
}
func (a *AuthenticationMethodSelector) AuthenticationProtocol(
	req socks6.Request,
	methodId byte,
	conn io.ReadWriteCloser,
) (bool, ClientID) {
	data := req.MethodData[methodId]
	method := a.idMap[methodId]
	return method.AuthenticationProtocol(data, conn)
}

// client's name, for logging etc
type ClientID string

type AuthenticationMethod interface {
	ID() (byte, string)
	Authenticate(data []byte) (bool, ClientID)
	InteractiveAuthenticate(data []byte) bool
	AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) (bool, ClientID)
}

type NoneAuthentication struct {
}

func (n NoneAuthentication) ID() (byte, string) {
	return 0, "none"
}
func (n NoneAuthentication) Authenticate(data []byte) (bool, string) {
	return true, ""
}
func (n NoneAuthentication) InteractiveAuthenticate(data []byte) bool {
	return false
}
func (n NoneAuthentication) AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) (bool, string) {
	return true, ""
}

type UsernamePasswordAuthentication struct {
}

func (n UsernamePasswordAuthentication) ID() (byte, string) {
	return 2, "username-password"
}
func (n UsernamePasswordAuthentication) Authenticate(data []byte) (bool, string) {
	return true, ""
}
func (n UsernamePasswordAuthentication) InteractiveAuthenticate(data []byte) bool {
	return false
}
func (n UsernamePasswordAuthentication) AuthenticationProtocol(data []byte, conn io.ReadWriteCloser) (bool, string) {
	return n.Authenticate(data)
}

type DefaultAuthenticator struct {
	DisableSession bool
	DisableToken   bool
	MethodSelector AuthenticationMethodSelector
	sessions       map[uint64]ClientID // TODO: id size is not always 8B,session timeout
}

// todo: authenticate return this one instead
type AuthenticationResult struct {
	Success        bool
	SelectedMethod byte
	ClientID       ClientID
	SessionID      []byte
}

func (d DefaultAuthenticator) Authenticate(req socks6.Request) (bool, socks6.AuthenticationReply, byte, ClientID) {
	if !d.DisableSession && req.SessionID != nil {
		sid64 := binary.BigEndian.Uint64(req.SessionID)
		if d.sessions[sid64] == "" || req.RequestTeardown {
			// fail fast
			sar := socks6.AuthenticationReply{
				Type:         socks6.AuthenticationReplyFail,
				InSession:    true,
				SessionValid: false,
			}
			return false, sar, 0, ""
		}
		// TODO:token
	}

	sar := socks6.AuthenticationReply{
		Type: socks6.AuthenticationReplySuccess,
	}
	return true, sar, 0, ""
}
