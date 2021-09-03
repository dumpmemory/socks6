package socket

import (
	"log"
	"syscall"

	"github.com/studentmain/socks6/message"
	"golang.org/x/sys/windows"
)

func setAndValidateSockoptInt(fd syscall.Handle, level int, opt int, value int) int {
	err := syscall.SetsockoptInt(fd, level, opt, value)
	if err != nil {
		printSetsockoptError(err)
	}
	v, err := syscall.GetsockoptInt(fd, level, opt)
	if err != nil {
		printSetsockoptError(err)
	}
	return v
}

func printSetsockoptError(err error) {
	eno := err.(syscall.Errno)
	if eno != windows.WSAENOPROTOOPT {
		log.Print(err)
	}
}

func applyIPOption(fd uintptr, opt message.StackOptionInfo) message.StackOptionInfo {
	rep := map[int]interface{}{}
	h := syscall.Handle(fd)

	if df, ok := opt[message.StackOptionIPNoFragment]; ok {
		val := setsockoptBtoi(df.(bool))
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, ip_df, val)
		real := v != 0
		rep[message.StackOptionIPNoFragment] = real
	}

	if ttl, ok := opt[message.StackOptionIPTTL]; ok {
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL, int(ttl.(byte)))
		rep[message.StackOptionIPTTL] = byte(v)
	}
	if tos, ok := opt[message.StackOptionIPTOS]; ok {
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TOS, int(tos.(byte)))
		rep[message.StackOptionIPTOS] = byte(v)
	}
	return rep
}

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
