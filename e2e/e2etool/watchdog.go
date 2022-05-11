package e2etool

import (
	"time"
)

func WatchDog() {
	wd(1 * time.Second)
}

func WatchDog10s() {
	wd(10 * time.Second)
}

func wd(t time.Duration) {
	go func() {
		<-time.After(t)
		panic("test timeout")
	}()
}
