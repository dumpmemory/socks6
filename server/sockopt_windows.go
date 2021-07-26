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
func setsocks6optTcpClient(fd uintptr, opt socks6.StackOptionData) socks6.StackOptionData {
	const DF = 14
	rep := socks6.StackOptionData{}
	h := syscall.Handle(fd)
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
		v, err := syscall.GetsockoptInt(h, syscall.IPPROTO_IP, DF)
		if err != nil {
			printSetsockoptError(err)
		}
		real := byte(v)
		rep.TTL = &real
	}
	// no tfo and mptcp for all platform

	return rep
}
