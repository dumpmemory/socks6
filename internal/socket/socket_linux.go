package socket

import (
	"log"
	"syscall"

	"github.com/studentmain/socks6/message"
)

func setAndValidateSockoptInt(fd int, level int, opt int, value int) int {
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
func setAndValidateSockoptByte(fd int, level int, opt int, value byte) int {
	err := syscall.SetsockoptByte(fd, level, opt, value)
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
	if eno != syscall.ENOPROTOOPT {
		log.Print(err)
	}
}

func applyIPOption(fd uintptr, opt message.StackOptionInfo) message.StackOptionInfo {
	rep := map[int]interface{}{}
	ifd := int(fd)
	if df, ok := opt[message.StackOptionIPNoFragment]; ok {
		val := setsockoptBtoi(df.(bool))
		v := setAndValidateSockoptInt(ifd, syscall.IPPROTO_IP, ip_df, val)
		real := v != 0
		rep[message.StackOptionIPNoFragment] = real
	}
	if ttl, ok := opt[message.StackOptionIPTTL]; ok {
		v := setAndValidateSockoptByte(ifd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl.(byte))
		rep[message.StackOptionIPTTL] = byte(v)
	}
	if tos, ok := opt[message.StackOptionIPTOS]; ok {
		v := setAndValidateSockoptByte(ifd, syscall.IPPROTO_IP, syscall.IP_TOS, tos.(byte))
		rep[message.StackOptionIPTOS] = byte(v)
	}
	return rep
}
func ConvertErrno(e syscall.Errno) syscall.Errno {
	return e
}
