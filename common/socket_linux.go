package common

import (
	"syscall"
)

func ConvertSocketErrno(e syscall.Errno) syscall.Errno {
	return e
}
