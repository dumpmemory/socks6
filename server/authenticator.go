package server

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"math"
	"sort"
	"sync"
	"time"

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
	if len(a.idMap) == 0 {
		return AuthenticationResult{
			Success:        true,
			SelectedMethod: socks6.AuthenticationMethodNone,
		}
	}
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
	Users map[string]string
}

func (n UsernamePasswordAuthentication) ID() (byte, string) {
	return 2, "username-password"
}
func (n UsernamePasswordAuthentication) Authenticate(data []byte) AuthenticationResult {
	log.Print(data)
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
	SessionTimeout time.Duration

	sessions sync.Map
}

type SessionInfo struct {
	SessionID  []byte
	ClientID   ClientID
	lastActive time.Time

	allocateLimit uint32
	useToken      bool
	smallestToken uint32
	biggestToken  uint32
	// [](start,end) ?
	unorderedToken []uint32
}

func NewDefaultAuthenticator() DefaultAuthenticator {
	da := DefaultAuthenticator{
		sessions:       sync.Map{},
		SessionTimeout: 5 * time.Minute,
	}
	go da.clearTimeoutSession()
	return da
}

func (s *SessionInfo) AllocateTokens(count uint32) (uint32, uint32) {
	if count == 0 {
		count = s.allocateLimit
		if count == 0 {
			count = 1024
		}
	}
	// limit window size to reduce res usage
	if count > 4096 {
		count = 4096
	}
	if count < 32 {
		count = 32
	}
	s.allocateLimit = count / 8
	b := []byte{0, 0, 0, 0}
	if !s.useToken {
		_, err := rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		s.smallestToken = binary.BigEndian.Uint32(b)
		s.useToken = true
	}
	s.biggestToken = s.smallestToken + count
	return s.smallestToken, count
}

func (s *SessionInfo) SpendToken(token uint32) (ok bool, alloc bool) {
	if !s.useToken {
		return false, false
	}
	for _, t := range s.unorderedToken {
		if token == t {
			return false, false
		}
	}
	spent := false
	// not overflow
	if s.smallestToken < s.biggestToken {
		if token >= s.smallestToken && token < s.biggestToken {
			spent = true
		}
	} else {
		if (token < s.smallestToken) == (token < s.biggestToken) {
			spent = true
		}
	}
	if !spent {
		return false, false
	}
	// update remain token
	if token == s.smallestToken+1 {
		s.smallestToken++
		// assume sorted
		s.unorderedToken = s.unorderedToken[1:]
	} else {
		s.unorderedToken = append(s.unorderedToken, token)
		sort.Slice(s.unorderedToken, func(i, j int) bool {
			ti := s.unorderedToken[i]
			tj := s.unorderedToken[j]
			iroll := ti < s.smallestToken
			jroll := tj < s.smallestToken

			if iroll == jroll {
				return ti < tj
			}
			//i rolled, so ti>tj
			if iroll {
				return false
			}
			return true
		})
		expectSt := s.smallestToken
		n := 0
		for k, v := range s.unorderedToken {
			if expectSt == math.MaxUint32 {
				if v != 0 {
					n = k
					break
				}
				expectSt = 0
				continue
			}
			if v != expectSt+1 {
				n = k
				break
			}
			expectSt++
		}
		s.smallestToken = expectSt
		s.unorderedToken = s.unorderedToken[n:]
	}

	reallocate := s.biggestToken-s.smallestToken < s.allocateLimit/4

	return true, reallocate
}

type Authenticaticator interface {
	Authenticaticate(req socks6.Request) (AuthenticationResult, socks6.AuthenticationReply)
}

type AuthenticationResult struct {
	Success        bool
	SelectedMethod byte
	ClientID       ClientID
	SessionID      []byte
}

const sessionLength = 8

func (d *DefaultAuthenticator) getSessionHash(id []byte) uint64 {
	h := sha3.NewShake128()
	h.Write(id)
	b := make([]byte, 8)
	h.Read(b)
	return binary.BigEndian.Uint64(b)
}

func (d *DefaultAuthenticator) Authenticate(req socks6.Request) (AuthenticationResult, socks6.AuthenticationReply) {
	reply := socks6.AuthenticationReply{
		Type: socks6.AuthenticationReplyFail,
	}
	if !d.DisableSession && req.SessionID != nil {
		return d.authenticateSession(req)
	}
	result := d.MethodSelector.Authenticate(req)
	if result.SelectedMethod != 0 {
		reply.SelectedMethod = result.SelectedMethod
	}
	if !result.Success {
		return result, reply
	}

	// auth ok
	reply.Type = socks6.AuthenticationReplySuccess

	if !d.DisableSession && req.RequestSession {
		result.SessionID = make([]byte, sessionLength)
		rand.Read(result.SessionID)
		session := SessionInfo{
			SessionID:  result.SessionID,
			ClientID:   result.ClientID,
			lastActive: time.Now(),
		}
		sHash := d.getSessionHash(session.SessionID)
		if !d.DisableToken && req.RequestToken > 0 {
			reply.NewWindowBase, reply.NewWindowSize = session.AllocateTokens(req.RequestToken)
		}
		d.sessions.Store(sHash, session)
	}
	return result, reply
}

func (d *DefaultAuthenticator) authenticateSession(req socks6.Request) (AuthenticationResult, socks6.AuthenticationReply) {
	sHash := d.getSessionHash(req.SessionID)
	_s, ok := d.sessions.Load(sHash)
	session := _s.(*SessionInfo)
	reply := socks6.AuthenticationReply{
		Type:      socks6.AuthenticationReplyFail,
		InSession: true,
	}
	if req.RequestTeardown {
		d.sessions.Delete(sHash)
	}
	// session check
	if !ok || req.RequestTeardown {
		reply.SessionValid = false
		return AuthenticationResult{
			Success: false,
		}, reply
	}

	reply.SessionValid = true

	if !d.DisableToken && req.UseToken {
		reply.UsingToken = true

		// token check
		ok, reallocate := session.SpendToken(req.TokenToSpend)
		if !ok {
			reply.TokenValid = false
			return AuthenticationResult{
				Success: false,
			}, reply
		}
		reply.TokenValid = true
		if reallocate || req.RequestToken > 0 {
			reply.NewWindowBase, reply.NewWindowSize = session.AllocateTokens(req.RequestToken)
		}
	}
	reply.Type = socks6.AuthenticationReplySuccess
	session.lastActive = time.Now()

	return AuthenticationResult{
		Success:   true,
		SessionID: session.SessionID,
		ClientID:  session.ClientID,
	}, reply
}

func (d *DefaultAuthenticator) clearTimeoutSession() {
	for {
		time.Sleep(d.SessionTimeout / 5)

		now := time.Now()
		d.sessions.Range(func(key, value interface{}) bool {
			t := value.(*SessionInfo).lastActive
			dt := now.Sub(t)
			if dt > d.SessionTimeout {
				d.sessions.Delete(key)
			}
			return true
		})
	}
}
