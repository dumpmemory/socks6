package socket

import (
	"syscall"
)

func ConvertErrno(e syscall.Errno) syscall.Errno {
	return e
}
