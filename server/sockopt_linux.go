package server

import (
	"log"
	"syscall"

	"github.com/studentmain/socks6"
)

func printSetsockoptError(err error) {
	eno := err.(syscall.Errno)
	if eno != syscall.ENOPROTOOPT {
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
func setsocks6optIp(fd uintptr, opt socks6.StackOptionData) socks6.StackOptionData {
	const DF = 14
	rep := socks6.StackOptionData{}
	h := int(fd) // TODO???
	if opt.DF != nil {
		val := setsockoptBtoi(*opt.DF)
		err := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, DF, val)
		if err != nil {
			printSetsockoptError(err)
		}
		v, err := syscall.GetsockoptInt(h, syscall.IPPROTO_IP, DF)
		if err != nil {
			printSetsockoptError(err)
		}
		real := v != 0
		rep.DF = &real
	}
	if opt.TTL != nil {
		err := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL, int(*opt.TTL))
		if err != nil {
			printSetsockoptError(err)
		}
		v, err := syscall.GetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL)
		if err != nil {
			printSetsockoptError(err)
		}
		real := byte(v)
		rep.TTL = &real
	}
	if opt.TOS != nil {
		err := syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TOS, int(*opt.TOS))
		if err != nil {
			printSetsockoptError(err)
		}
		v, err := syscall.GetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TOS)
		if err != nil {
			printSetsockoptError(err)
		}
		real := byte(v)
		rep.TTL = &real
	}
	return rep
}

func setsocks6optTcpClient(fd uintptr, opt socks6.StackOptionData) socks6.StackOptionData {

	// no tfo and mptcp for all platform

	return setsocks6optIp(fd, opt)
}

func setsocks6optTcpServer(fd uintptr, opt socks6.StackOptionData) socks6.StackOptionData {
	return setsocks6optIp(fd, opt)
}

func setsocks6optUdp(fd uintptr, opt socks6.StackOptionData) socks6.StackOptionData {
	return setsocks6optIp(fd, opt)
}

func convertErrno(e syscall.Errno) syscall.Errno {
	return e
}
