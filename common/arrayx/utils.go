package arrayx

import (
	"sort"
)

// Dup create a duplicate of input byte array
func Dup(i []byte) []byte {
	o := make([]byte, len(i))
	copy(o, i)
	return o
}

func PaddedLen(l int, align int) int {
	return (l + align - 1) / align * align
}

// SortByte ascending sort a byte array in position
func SortByte(b []byte) {
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
}
