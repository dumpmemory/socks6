package shadowsocks2021

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/studentmain/socks6/internal"
)

type SSConn struct {
	net.Conn

	key [32]byte

	rc   cipher.AEAD
	rctr []byte
	rb   bytes.Buffer

	wc   cipher.AEAD
	wctr []byte

	factory func(key [32]byte) cipher.AEAD
}

func (s *SSConn) Read(b []byte) (int, error) {
	if s.rc == nil {
		l := s.factory(s.key).NonceSize()
		s.rctr = make([]byte, l)
		iv := new([32]byte)
		ivs := iv[:]
		if _, err := io.ReadFull(s.Conn, ivs); err != nil {
			return 0, err
		}

		s.rc = s.factory(nckdf(s.key, *iv))
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
		l := s.factory(s.key).NonceSize()
		s.wctr = make([]byte, l)
		iv := new([32]byte)
		ivs := iv[:]
		if _, err := rand.Read(ivs); err != nil {
			return 0, err
		}
		if _, err := s.Conn.Write(ivs); err != nil {
			return 0, err
		}

		s.wc = s.factory(nckdf(s.key, *iv))
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

func NewSSConn(conn net.Conn, kk []byte) *SSConn {
	k := nhkdf(kk)
	sc := SSConn{
		Conn: conn,
		key:  k,
	}
	sc.factory = func(key [32]byte) cipher.AEAD {
		a, err := aes.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		g, err := cipher.NewGCM(a)
		if err != nil {
			panic(err)
		}
		return g
	}
	return &sc
}

func nhkdf(password []byte) [32]byte {
	return sha256.Sum256(append(password, []byte("shadowsocks2021-key")...))
}

func nckdf(key, iv [32]byte) [32]byte {
	a := internal.Must2(aes.NewCipher(key[:]))
	ret := new([32]byte)
	a.Encrypt(iv[:16], ret[:16])
	a.Encrypt(iv[16:], ret[16:])
	return *ret
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
