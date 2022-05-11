package e2e_test

import (
	"log"

	"github.com/studentmain/socks6/common/lg"
)

func init() {
	lg.EnableColor()
	lg.MinimalLevel = lg.LvDebug
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}
