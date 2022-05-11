// lg is a wrapper of builtin log package
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
	LvWarning: "Warn ",
	LvInfo:    "Info ",
	LvTrace:   "Trace",
	LvDebug:   "Debug",
}

type Logger func(lv Level, str string)

var Backend Logger = func(lv Level, str string) {
	msg := PrependLevel(lv, str)
	log.Output(4, msg)
}

var levelColorPrefix = map[Level]string{
	LvFatal:   "97;101",
	LvPanic:   "97;101",
	LvError:   "31",
	LvWarning: "33",
	LvInfo:    "34",
	LvTrace:   "37",
	LvDebug:   "90",
}

func coloredLogger(lv Level, str string) {
	log.Output(4, fmt.Sprintf("\x1b[%sm[%s] \x1b[0m", levelColorPrefix[lv], levelPrefix[lv])+str)
}

func EnableColor() {
	Backend = coloredLogger
}

var MinimalLevel Level = LvInfo

func PrependLevel(lv Level, s string) string {
	return fmt.Sprintf("[%s] ", levelPrefix[lv]) + s
}

func lgprintf(lv Level, format string, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	pf := fmt.Sprintf(format, v...)
	Backend(lv, pf)
}

func lgprint(lv Level, v ...interface{}) {
	if lv > MinimalLevel {
		return
	}
	ln := fmt.Sprintln(v...)
	Backend(lv, ln)
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
