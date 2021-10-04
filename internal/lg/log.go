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

func lgprintf(lv Level, format string, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	f := fmt.Sprintf("[%s] %s", levelPrefix[lv], format)
	msg := fmt.Sprintf(f, v...)
	log.Output(3, msg)
}

func lgprint(lv Level, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	f := fmt.Sprintf("[%s]", levelPrefix[lv])
	msg := fmt.Sprintln(append([]interface{}{f}, v...)...)
	log.Output(3, msg)
}

func Fatalf(format string, v ...interface{}) {
	lgprintf(LvFatal, format, v...)
	os.Exit(1)
}

func Panicf(format string, v ...interface{}) {
	lgprintf(LvPanic, format, v...)
	e := fmt.Sprintf(format, v...)
	panic(e)
}

func Errorf(format string, v ...interface{}) {
	lgprintf(LvError, format, v...)
}

func Warningf(format string, v ...interface{}) {
	lgprintf(LvWarning, format, v...)
}

func Infof(format string, v ...interface{}) {
	lgprintf(LvInfo, format, v...)
}

func Tracef(format string, v ...interface{}) {
	lgprintf(LvTrace, format, v...)
}

func Debugf(format string, v ...interface{}) {
	lgprintf(LvDebug, format, v...)
}

func Fatal(v ...interface{}) {
	lgprint(LvFatal, v...)
	os.Exit(1)
}
func Panic(v ...interface{}) {
	lgprint(LvPanic, v...)
	for i := 0; i < len(v); i++ {
		if err, ok := v[i].(error); ok {
			panic(err)
		}
	}
	panic(v[0])
}

func Error(v ...interface{}) {
	lgprint(LvError, v...)
}

func Warning(v ...interface{}) {
	lgprint(LvWarning, v...)
}

func Info(v ...interface{}) {
	lgprint(LvInfo, v...)
}

func Trace(v ...interface{}) {
	lgprint(LvTrace, v...)
}

func Debug(v ...interface{}) {
	lgprint(LvDebug, v...)
}
