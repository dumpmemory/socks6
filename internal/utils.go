package internal

import (
	"sort"

	"github.com/golang/glog"
)

func ByteArrayEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Dup(i []byte) []byte {
	o := make([]byte, len(i))
	copy(o, i)
	return o
}

func PaddedLen(l int, align int) int {
	return (l + align - 1) / align * align
}

func SortByte(b []byte) {
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
}

func Must2(v interface{}, e error) interface{} {
	if e != nil {
		glog.Fatal(e)
	}
	return v
}

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

func (p *BytesPool) Rent() []byte {
	count := len(p.ch)
	if count == 0 {
		return make([]byte, p.l)
	}
	return <-p.ch
}

func (p *BytesPool) Return(b []byte) {
	if len(b) != p.l {
		panic("please return all bytes you rented!")
	}
	capacity := cap(p.ch)

	if len(p.ch) == capacity {
		glog.Warning("returned more than rented")
		ch2 := make(chan []byte, capacity*2)
		for i := 0; i < capacity; i++ {
			ch2 <- <-p.ch
		}
		p.ch = ch2
	}
	p.ch <- b
}

var BytesPool64k = NewBytesPool(65536, 16)
var BytesPool4k = NewBytesPool(4096, 128)
var BytesPool256 = NewBytesPool(256, 128)
var BytesPool16 = NewBytesPool(16, 128)
