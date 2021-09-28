package socket

import (
	"log"
	"syscall"

	"github.com/studentmain/socks6/message"
	"golang.org/x/sys/windows"
)


func ConvertErrno(e syscall.Errno) syscall.Errno {
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
