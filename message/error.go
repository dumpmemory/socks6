package message

import (
	"errors"
	"fmt"

	"github.com/studentmain/socks6/common"
	"github.com/studentmain/socks6/common/lg"
)

var ErrMessageProcess = errors.New("message error")

var ErrEnumValue = common.LeveledError{
	Message: "invalid enum value",
	Base:    ErrMessageProcess,
	Level:   lg.LvError,
}
var ErrFormat = common.LeveledError{
	Message: "format error",
	Base:    ErrMessageProcess,
	Level:   lg.LvError,
}
var ErrAddressTypeNotSupport = common.LeveledError{
	Message: "unsupported address type",
	Base:    ErrMessageProcess,
	Level:   lg.LvError,
}
var ErrBufferSize = common.LeveledError{
	Message: "invalid buffer size",
	Base:    ErrMessageProcess,
	Level:   lg.LvWarning,
}
var ErrOptionTooLong = common.LeveledError{
	Message: "option too long",
	Base:    ErrMessageProcess,
	Level:   lg.LvWarning,
}

var ErrStackOptionNoLeg = common.LeveledError{
	Message: "stack option should have at least one leg",
	Base:    ErrMessageProcess,
	Level:   lg.LvWarning,
}
var errVersionMismatch = common.LeveledError{
	Message: "version mismatch",
	Level:   lg.LvInfo,
}

func NewErrVersionMismatch(v int, b []byte) error {
	cp := errVersionMismatch.WithVerbose("")
	cp.Base = ErrVersionMismatch{
		Version:       v,
		ConsumedBytes: b,
	}
	return cp
}

type ErrVersionMismatch struct {
	Version       int
	ConsumedBytes []byte
}

func (e ErrVersionMismatch) Error() string {
	return fmt.Sprintf("version %d not supported", e.Version)
}
func (e ErrVersionMismatch) Unwrap() error {
	return ErrMessageProcess
}
func (e ErrVersionMismatch) Is(e2 error) bool {
	_, ok := e2.(ErrVersionMismatch)
	return ok
}
