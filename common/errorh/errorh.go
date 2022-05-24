package errorh

import "github.com/studentmain/socks6/common/lg"

// Must2 passthrough first parameter, panic when second parameter is not nil
func Must2[T any](v T, e error) T {
	if e != nil {
		lg.Panic(e)
	}
	return v
}
