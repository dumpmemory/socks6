package auth

import (
	"math"

	"github.com/studentmain/socks6/internal"
)

type serverSession struct {
	id         []byte
	windowBase uint32
	window     internal.BoolArr
	popcnt     int
	connCount  int
}

func newServerSession(idSize int) *serverSession {
	return &serverSession{
		id:     internal.RandBytes(idSize),
		window: internal.NewBoolArr(0),
	}
}

func (s *serverSession) checkToken(t uint32) bool {
	offset := t - s.windowBase
	if offset > uint32(s.window.Length()) {
		return false
	}

	if s.window.Get(int(offset)) {
		return false
	}

	s.window.Set(int(offset), true)
	s.popcnt++
	return true
}

func (s *serverSession) allocateWindow(size uint32) (bool, uint32, uint32) {
	origSize := s.window.Length()
	if origSize == 0 {
		s.windowBase = internal.RandUint32()
		s.window = internal.NewBoolArr(int(size))
		return true, s.windowBase, size
	}
	if !s.window.Get(0) {
		return false, s.windowBase, uint32(origSize)
	}
	spentRate := float64(s.popcnt) / float64(origSize)
	baseOffsetF := math.Floor(spentRate * float64(origSize))
	baseOffset := internal.PaddedLen(int(baseOffsetF), 8) / 8
	s.windowBase += uint32(baseOffset)
	dst := s.window

	// resize
	if size > uint32(origSize) {
		dst = make(internal.BoolArr, size)
	}
	// resized or window shifted
	if baseOffset > 0 || size > uint32(origSize) {
		copy(dst, s.window[baseOffset:])
	}
	s.window = dst
	return true, s.windowBase, uint32(s.window.Length())
}
