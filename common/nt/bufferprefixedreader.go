package nt

import (
	"io"
	"net"
)

// BufferPrefixedReader is an io.Reader which first read from Buffer, then from another io.Reader
type BufferPrefixedReader struct {
	Reader io.Reader
	Buffer []byte

	readFn func([]byte) (int, error)
	ptr    int
}

func NewBufferPrefixedReader(r io.Reader, b []byte) *BufferPrefixedReader {
	rr := BufferPrefixedReader{
		Reader: r,
		Buffer: b,
	}
	rr.readFn = rr.readBuffer
	return &rr
}

// Read implements io.Reader
func (br *BufferPrefixedReader) Read(b []byte) (int, error) {
	return br.readFn(b)
}
func (br *BufferPrefixedReader) readBuffer(b []byte) (int, error) {
	if br.ptr >= len(br.Buffer) {
		br.readFn = br.Reader.Read
		return br.Reader.Read(b)
	}

	bf := br.Buffer[br.ptr:]
	lb := len(b)
	lbf := len(bf)
	if lb <= lbf {
		// remaining buffer is enough
		copy(b, bf)
		br.ptr += lb
		return lb, nil
	}

	copy(b, bf)
	br.readFn = br.Reader.Read
	n, err := br.Reader.Read(b[lbf:])
	if err != nil {
		return 0, err
	}
	br.ptr = len(br.Buffer)
	return n + lbf, nil
}

type netConn net.Conn

// BufferPrefixedConn is a net.Conn with BufferPrefixedReader
type BufferPrefixedConn struct {
	netConn
	BufferPrefixedReader
}

func (bc *BufferPrefixedConn) Read(b []byte) (int, error) {
	return bc.BufferPrefixedReader.Read(b)
}

func NewBufferPrefixedConn(c net.Conn, b []byte) *BufferPrefixedConn {
	return &BufferPrefixedConn{
		netConn:              c,
		BufferPrefixedReader: *NewBufferPrefixedReader(c, b),
	}
}
