package internal

import "github.com/studentmain/socks6/common/lg"

// BytesPool is a fixed size byte array pool
// byte array is fized size, but byte array count is increased automatically
type BytesPool struct {
	ch chan []byte
	l  int
}

func NewBytesPool(bytesSize, poolSize int) *BytesPool {
	return &BytesPool{
		ch: make(chan []byte, poolSize),
		l:  bytesSize,
	}
}

// Rent rent a byte array from pool, length is determined when creating pool
func (p *BytesPool) Rent() []byte {
	count := len(p.ch)
	if count == 0 {
		return make([]byte, p.l)
	}
	return <-p.ch
}

// Return return a rented byte array to pool\
// always return what exactly you rented.
func (p *BytesPool) Return(b []byte) {
	if len(b) != p.l {
		lg.Panic("please return all bytes you rented!")
	}
	capacity := cap(p.ch)

	if len(p.ch) == capacity {
		lg.Warning("returned more than rented")
		ch2 := make(chan []byte, capacity*2)
		for i := 0; i < capacity; i++ {
			ch2 <- <-p.ch
		}
		p.ch = ch2
	}
	p.ch <- b
}

// BytesPool64k is a BytesPool with array size 65536, primarily used as large header and UDP recieve buffer
var BytesPool64k = NewBytesPool(65536, 16)

// BytesPool4k is a BytesPool with array size 4096, used as message forwarding buffer
var BytesPool4k = NewBytesPool(4096, 128)

// BytesPool256 is a BytesPool with array size 256, used as header deserialize buffer
var BytesPool256 = NewBytesPool(256, 128)

// BytesPool256 is a BytesPool with array size 16
var BytesPool16 = NewBytesPool(16, 128)
