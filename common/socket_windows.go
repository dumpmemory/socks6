package common

import (
	"log"
	"syscall"

	"golang.org/x/sys/windows"
)

func ConvertSocketErrno(e syscall.Errno) syscall.Errno {
	switch e {
	case windows.WSAENOPROTOOPT:
		return syscall.ENOPROTOOPT
	case windows.WSAENETUNREACH:
		return syscall.ENETUNREACH
	case windows.WSAEHOSTUNREACH:
		return syscall.EHOSTUNREACH
	case windows.WSAEREFUSED:
		return syscall.ECONNREFUSED
	case windows.WSAETIMEDOUT:
	default:
		return e
	}
	return e
}
