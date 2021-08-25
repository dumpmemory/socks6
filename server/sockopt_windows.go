package server

import (
	"log"
	"syscall"

	"github.com/studentmain/socks6"
	"golang.org/x/sys/windows"
)

func printSetsockoptError(err error) {
	eno := err.(syscall.Errno)
	if eno != windows.WSAENOPROTOOPT {
		log.Print(err)
	}
}
func setsockoptBtoi(b bool) int {
	val := 0
	if b {
		val = 1
	}
	return val
}

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

func setsocks6optIp(fd uintptr, opt StackOptionInfo) StackOptionInfo {
	const DF = 14
	rep := map[int]interface{}{}
	h := syscall.Handle(fd)
	if df, ok := opt[socks6.StackOptionIPNoFragment]; ok {
		val := setsockoptBtoi(df.(bool))
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, DF, val)
		real := v != 0
		rep[socks6.StackOptionIPNoFragment] = real
	}

	if ttl, ok := opt[socks6.StackOptionIPTTL]; ok {
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL, int(ttl.(byte)))
		rep[socks6.StackOptionIPTTL] = byte(v)
	}
	if tos, ok := opt[socks6.StackOptionIPTOS]; ok {
		v := setAndValidateSockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TOS, int(tos.(byte)))
		rep[socks6.StackOptionIPTOS] = byte(v)
	}
	return rep
}

func setsocks6optTcpClient(fd uintptr, opt StackOptionInfo) StackOptionInfo {

	// no tfo and mptcp for all platform

	return setsocks6optIp(fd, opt)
}

func setsocks6optTcpServer(fd uintptr, opt StackOptionInfo) StackOptionInfo {
	return setsocks6optIp(fd, opt)
}

func setsocks6optUdp(fd uintptr, opt StackOptionInfo) StackOptionInfo {
	return setsocks6optIp(fd, opt)
}

func convertErrno(e syscall.Errno) syscall.Errno {
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
