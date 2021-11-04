package ssocks6

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type SSConn struct {
	net.Conn

	key []byte

	rc   cipher.AEAD
	rctr []byte
	rb   bytes.Buffer

	wc   cipher.AEAD
	wctr []byte

	factory func(key, iv []byte) cipher.AEAD
}

func (s *SSConn) Read(b []byte) (int, error) {
	if s.rc == nil {
		l := s.factory(s.key, []byte{}).NonceSize()
		s.rctr = make([]byte, l)
		iv := make([]byte, l)
		if _, err := io.ReadFull(s.Conn, iv); err != nil {
			return 0, err
		}

		s.rc = s.factory(kdf2(s.key, iv), iv)
	}

	for s.rb.Len() < len(b) {
		b, err := s.readBlk()
		if err != nil {
			return 0, err
		}
		s.rb.Write(b)
	}
	return s.rb.Read(b)
}

func (s *SSConn) readBlk() ([]byte, error) {
	o := s.rc.Overhead()
	buf := make([]byte, 2+o)
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return nil, err
	}
	if _, err := s.rc.Open(buf[:0], s.rctr, buf, nil); err != nil {
		return nil, err
	}
	increment(s.rctr)
	l := binary.BigEndian.Uint16(buf)
	buf = make([]byte, int(l)+o)
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return nil, err
	}
	if _, err := s.rc.Open(buf[:0], s.rctr, buf, nil); err != nil {
		return nil, err
	}
	increment(s.rctr)
	return buf, nil
}

func (s *SSConn) Write(b []byte) (int, error) {
	if s.wc == nil {
		l := s.factory(s.key, []byte{}).NonceSize()
		s.wctr = make([]byte, l)
		iv := make([]byte, l)
		if _, err := rand.Read(iv); err != nil {
			return 0, err
		}
		if _, err := s.Conn.Write(iv); err != nil {
			return 0, err
		}

		s.wc = s.factory(kdf2(s.key, iv), iv)
	}
	ll := 2
	if len(b) > ll {
		ll = len(b)
	}
	b2 := make([]byte, ll+s.wc.Overhead())
	binary.BigEndian.PutUint16(b2, uint16(len(b)))
	s.wc.Seal(b2[:0], s.wctr, b2[:2], nil)
	if _, err := s.Conn.Write(b2[:2+s.wc.Overhead()]); err != nil {
		return 0, err
	}
	increment(s.wctr)
	s.wc.Seal(b2, s.wctr, b, nil)
	if _, err := s.Conn.Write(b2[:len(b)+s.wc.Overhead()]); err != nil {
		return 0, err
	}
	increment(s.wctr)
	return len(b), nil
}

func NewSSConn(conn net.Conn, method string, kk []byte) *SSConn {
	k := kdf1(kk, 32)
	sc := SSConn{
		Conn: conn,
		key:  k,
	}
	switch method {
	case "aes-256-gcm":
		sc.factory = func(key, iv []byte) cipher.AEAD {
			a, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			g, err := cipher.NewGCM(a)
			if err != nil {
				panic(err)
			}
			return g
		}
	case "chacha20-poly1305":
		sc.factory = func(key, iv []byte) cipher.AEAD {
			c, err := chacha20poly1305.New(key)
			if err != nil {
				panic(err)
			}
			return c
		}
	}
	return &sc
}

func kdf1(password []byte, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

func kdf2(k, s []byte) []byte {
	r := make([]byte, len(s))
	kdf := hkdf.New(sha1.New, k, s, []byte("ssocks6-subkey"))
	if _, err := io.ReadFull(kdf, r); err != nil {
		panic(err)
	}
	return r
}

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func Relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}
