package e2etool

import (
	"time"

	"github.com/studentmain/socks6/common/lg"
)

func WatchDog() {
	wd(1 * time.Second)
}

func WatchDog10s() {
	wd(10 * time.Second)
}

func wd(t time.Duration) {
	go func() {
		before := time.Now()
		<-time.After(t)
		after := time.Now()
		if after.Sub(before) < t*11/10 {
			panic("test timeout")
		}
		lg.Warning("watchdog timeout, timer unstable, maybe in debug mode")
	}()
}
