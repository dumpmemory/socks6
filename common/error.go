package common

import (
	"fmt"

	"github.com/studentmain/socks6/internal/lg"
)

type LeveledError struct {
	Message string
	Verbose string
	Base    error
	Level   lg.Level
}

func (e LeveledError) Error() string {
	s := lg.PrependLevel(e.Level, e.Message)

	if e.Base != nil {
		s += e.Base.Error()
	}
	return s
}

func (e LeveledError) Unwrap() error {
	return e.Base
}

func (e LeveledError) Inner() error {
	return e.Base
}

func (e LeveledError) Is(e2 error) bool {
	if e3, ok := e2.(LeveledError); ok {
		return e3.Message == e.Message
	}
	return false
}

func (e LeveledError) WithVerbose(f string, v ...interface{}) LeveledError {
	return LeveledError{
		Message: e.Message,
		Verbose: fmt.Sprintf(f, v...),
		Base:    e.Base,
		Level:   e.Level,
	}
}
