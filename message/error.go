package message

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

func NewMessageError(msg string) error {
	return baseMessageError{
		msg: msg,
	}
}

var ErrEnumValue = NewMessageError("unexpected enum value")
var ErrVersion = NewMessageError("version is not 6")
var ErrFormat = NewMessageError("wrong message format")
var ErrAddressTypeNotSupport = NewMessageError("unknown address type")

type baseProtocolPoliceError struct {
	msg string
}

// ErrProtocolPolice is the error used to report non-standard behaviour
var ErrProtocolPolice = NewMessageError("consistency check fail")

func (e baseProtocolPoliceError) Error() string {
	return e.msg
}
func (e baseProtocolPoliceError) Unwrap() error {
	return ErrProtocolPolice
}

func newProtocolPoliceError(msg string) error {
	return baseProtocolPoliceError{
		msg: msg,
	}
}

var errProtocolPoliceBufferSize = newProtocolPoliceError("buffer size not allowed")

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
