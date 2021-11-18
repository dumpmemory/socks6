package socks6

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/studentmain/socks6/common/lg"
	"github.com/studentmain/socks6/internal"
)

func relayConnTuple(c, r net.Conn) string {
	return fmt.Sprintf("%s <==>> %s", conn5TupleIn(c), conn5TupleOut(r))
}

func conn3Tuple(c net.Conn) string {
	return fmt.Sprintf("%s(%s)", c.RemoteAddr().String(), connNet(c))
}

func conn5TupleIn(c net.Conn) string {
	return fmt.Sprintf("%s -(%s)-> %s", c.RemoteAddr().String(), connNet(c), c.LocalAddr().String())
}

func conn5TupleOut(c net.Conn) string {
	return fmt.Sprintf("%s -(%s)-> %s", c.LocalAddr().String(), connNet(c), c.RemoteAddr().String())
}

func connNet(c net.Conn) string {
	n := "?"
	switch c.(type) {
	case *net.TCPConn:
		n = "tcp"
	case *net.UDPConn:
		n = "udp"
	case *net.UnixConn:
		n = "unix"
	case *tls.Conn:
		n = "tls"
	case *dtls.Conn:
		n = "dtls"
	}
	return n
}

func relay(ctx context.Context, c, r net.Conn, timeout time.Duration) error {
	var wg sync.WaitGroup
	wg.Add(2)
	var err error = nil
	lg.Debugf("relay %s start", relayConnTuple(c, r))
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, c, r, timeout)
		// if already recorded an err, then another direction is already closed
		if e != nil && err == nil {
			err = e
			c.Close()
			r.Close()
		}
	}()
	go func() {
		defer wg.Done()
		e := relayOneDirection(ctx, r, c, timeout)
		if e != nil && err == nil {
			err = e
			c.Close()
			r.Close()
		}
	}()
	wg.Wait()

	lg.Debugf("relay %s done %s", relayConnTuple(c, r), err)
	if err == io.EOF {
		return nil
	}
	return err
}

func relayOneDirection(ctx context.Context, c1, c2 net.Conn, timeout time.Duration) error {
	var done error = nil
	buf := internal.BytesPool4k.Rent()
	defer internal.BytesPool4k.Return(buf)
	id := relayConnTuple(c1, c2)
	lg.Debugf("relayOneDirection %s start", id)
	go func() {
		<-ctx.Done()
		done = ctx.Err()
	}()
	defer lg.Debugf("relayOneDirection %s exit", id)
	// copy pasted from io.Copy with some modify
	for {
		c1.SetReadDeadline(time.Now().Add(timeout))
		nRead, eRead := c1.Read(buf)
		if done != nil {
			return done
		}

		if nRead > 0 {
			c2.SetWriteDeadline(time.Now().Add(timeout))
			nWrite, eWrite := c2.Write(buf[:nRead])
			if done != nil {
				return done
			}

			if eWrite != nil {
				lg.Debugf("relayOneDirection %s write error %s", id, eWrite)
				return eWrite
			}
			if nRead != nWrite {
				return io.ErrShortWrite
			}
		}
		if eRead != nil {
			lg.Debugf("relayOneDirection %s read error %s", id, eRead)
			return eRead
		}
	}
}
