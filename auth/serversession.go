package auth

import (
	"math"

	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/internal"
)

type serverSession struct {
	id         []byte
	windowBase uint32
	window     common.BoolArr
	popcnt     int
	connCount  int
}

func newServerSession(idSize int) *serverSession {
	return &serverSession{
		id:     internal.RandBytes(idSize),
		window: common.NewBoolArr(0),
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
	// zero window, alloc new window
	if origSize == 0 {
		s.windowBase = internal.RandUint32()
		s.window = common.NewBoolArr(int(size))
		return true, s.windowBase, size
	}
	// first not spent, reject
	if !s.window.Get(0) {
		return false, s.windowBase, uint32(origSize)
	}

	// windowBase+=s.popcnt, align to 8
	spentRatio := float64(s.popcnt) / float64(origSize)
	baseOffsetF := math.Floor(spentRatio * float64(origSize))
	baseOffset := internal.PaddedLen(int(baseOffsetF), 8) / 8
	s.windowBase += uint32(baseOffset)
	dst := s.window

	// resize, alloc new
	if size > uint32(origSize) {
		dst = make(common.BoolArr, size)
	}
	// resized or window shifted
	if baseOffset > 0 || size > uint32(origSize) {
		copy(dst, s.window[baseOffset:])
	}
	s.window = dst
	return true, s.windowBase, uint32(s.window.Length())
}
