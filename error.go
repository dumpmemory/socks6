package socks6

import (
	"errors"
	"strconv"
)

var ErrMessageProcess = errors.New("message error")

type baseMessageError struct {
	msg string
}

func (e baseMessageError) Error() string {
	return e.msg
}
func (e baseMessageError) Unwrap() error {
	return ErrMessageProcess
}

func newMessageError(msg string) error {
	return baseMessageError{
		msg: msg,
	}
}

type ErrTooShort struct {
	ExpectedLen int
}

func (e ErrTooShort) Error() string {
	return "buffer too short, need at least " + strconv.FormatInt(int64(e.ExpectedLen), 10)
}

func (e ErrTooShort) Unwrap() error {
	return ErrMessageProcess
}

func (e ErrTooShort) Is(t error) bool {
	_, ok := t.(ErrTooShort)
	return ok
}

func addExpectedLen(e error, l int) error {
	if ets, ok := e.(ErrTooShort); ok {
		return ErrTooShort{ExpectedLen: ets.ExpectedLen + l}
	}
	return e
}

var ErrEnumValue = newMessageError("unexpected enum value")
var ErrVersion = newMessageError("version is not 6")
var ErrFormat = newMessageError("wrong message format")
var ErrAddressTypeNotSupport = newMessageError("unknown address type")
