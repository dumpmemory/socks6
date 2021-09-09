package message

import (
	"errors"
	"fmt"
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

type ErrVersion struct {
	Version       int
	ConsumedBytes []byte
}

func (e ErrVersion) Error() string {
	return fmt.Sprintf("version %d not supported", e.Version)
}
func (e ErrVersion) Unwrap() error {
	return ErrMessageProcess
}
func (e ErrVersion) Is(e2 error) bool {
	_, ok := e2.(ErrVersion)
	return ok
}
