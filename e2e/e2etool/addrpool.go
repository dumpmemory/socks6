package e2etool

import (
	"fmt"

	"github.com/studentmain/socks6/internal"
)

const (
	startPort = 34535
	portCount = 128
)

func GetAddr() (string, uint16) {
	port := internal.RandUint16()%portCount + startPort
	return fmt.Sprintf("127.0.0.1:%d", port), port
}
