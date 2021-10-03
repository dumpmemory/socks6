// l is a log package
package lg

import (
	"fmt"
	"log"
	"os"
)

type Level int

const (
	LvFatal Level = iota
	LvPanic
	LvError
	LvWarning
	LvInfo
	LvTrace
	LvDebug
)

var levelPrefix = map[Level]string{
	LvFatal:   "Fatal",
	LvPanic:   "Panic",
	LvError:   "Error",
	LvWarning: "Warning",
	LvInfo:    "Info",
	LvTrace:   "Trace",
	LvDebug:   "Debug",
}

var MinimalLevel Level = LvInfo

func Printf(lv Level, format string, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	f := fmt.Sprintf("[%s] %s", levelPrefix[lv], format)
	log.Printf(f, v...)
}

func Print(lv Level, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	log.Print(v...)
}

func Fatalf(format string, v ...interface{}) {
	Printf(LvFatal, format, v...)
	os.Exit(1)
}

func Panicf(format string, v ...interface{}) {
	Printf(LvPanic, format, v...)
	e := fmt.Sprintf(format, v...)
	panic(e)
}

func Errorf(format string, v ...interface{}) {
	Printf(LvError, format, v...)
}

func Warningf(format string, v ...interface{}) {
	Printf(LvWarning, format, v...)
}

func Infof(format string, v ...interface{}) {
	Printf(LvInfo, format, v...)
}

func Tracef(format string, v ...interface{}) {
	Printf(LvTrace, format, v...)
}

func Debugf(format string, v ...interface{}) {
	Printf(LvDebug, format, v...)
}

func Fatal(v ...interface{}) {
	Print(LvFatal, v...)
	os.Exit(1)
}
func Panic(v ...interface{}) {
	Print(LvPanic, v...)
	panic(v[0])
}

func Error(v ...interface{}) {
	Print(LvError, v...)
}

func Warning(v ...interface{}) {
	Print(LvWarning, v...)
}

func Info(v ...interface{}) {
	Print(LvInfo, v...)
}

func Trace(v ...interface{}) {
	Print(LvTrace, v...)
}

func Debug(v ...interface{}) {
	Print(LvDebug, v...)
}
