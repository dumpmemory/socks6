package message

import "encoding/binary"

const OptionKindStreamID OptionKind = 0xfd10

func init() {
	SetOptionDataParser(OptionKindStreamID, func(b []byte) (OptionData, error) {
		if len(b) != 4 {
			return nil, ErrBufferSize.WithVerbose("expect 4 bytes buffer, actual %d bytes", len(b))
		}
		return StreamIDOptionData{ID: binary.BigEndian.Uint32(b)}, nil
	})
}

type StreamIDOptionData struct {
	ID uint32
}

var _ OptionData = StreamIDOptionData{}

func (s StreamIDOptionData) Marshal() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s.ID)
	return b
}
