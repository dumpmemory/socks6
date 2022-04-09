package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6/message"
)

func TestStackOptionID(t *testing.T) {
	assert.Equal(t, 258, message.StackOptionID(1, 2))
	a, b := message.SplitStackOptionID(258)
	assert.EqualValues(t, 1, a)
	assert.EqualValues(t, 2, b)
}

func legLevel(c, r bool, lv byte) byte {
	lv &= 0b00_111111
	if c {
		lv |= 0b0100_0000
	}
	if r {
		lv |= 0b1000_0000
	}
	return lv
}

func TestStackOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(true, false, 6), 10, 0, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: true,
				RemoteLeg: false,
				Level:     6,
				Code:      10,
				Data: &message.RawOptionData{
					Data: []byte{0, 0},
				},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 6), 10, 0, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     6,
				Code:      10,
				Data: &message.RawOptionData{
					Data: []byte{0, 0},
				},
			},
		})
}

func TestSetStackOptionDataParser(t *testing.T) {
	message.SetStackOptionDataParser(6, 1, func(b []byte) (message.StackOptionData, error) { return &message.TTLOptionData{TTL: 9}, nil })
	optionDataTest(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 6), 1, 9, 0,
	}, message.Option{
		Kind: message.OptionKindStack,
		Data: message.BaseStackOptionData{
			ClientLeg: false,
			RemoteLeg: true,
			Level:     6,
			Code:      1,
			Data: &message.TTLOptionData{
				TTL: 9,
			},
		},
	})
	message.SetStackOptionDataParser(6, 1, nil)
	optionDataTest(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 6), 1, 9, 0,
	}, message.Option{
		Kind: message.OptionKindStack,
		Data: message.BaseStackOptionData{
			ClientLeg: false,
			RemoteLeg: true,
			Level:     6,
			Code:      1,
			Data: &message.RawOptionData{
				Data: []byte{9, 0},
			},
		},
	})
}

func stackOptionDataTest(t *testing.T, obj message.StackOptionData, orig, new interface{}) {
	// serialize and deserialize are tested by optionDataTest
	assert.Equal(t, obj.GetData(), orig)
	obj.SetData(new)
	assert.Equal(t, obj.GetData(), new)
}

func TestRawOptionDataAsStackOptionData(t *testing.T) {
	stackOptionDataTest(t,
		&message.RawOptionData{
			Data: []byte{1},
		},
		[]byte{1}, []byte{1, 2, 3, 4, 5})
}

func TestTOSOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 1, 6, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelIP,
				Code:      message.StackOptionCodeTOS,
				Data: &message.TOSOptionData{
					TOS: 6,
				},
			},
		})
	stackOptionDataTest(t,
		&message.TOSOptionData{
			TOS: 9,
		}, byte(9), byte(15))
}

func TestHappyEyeballOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 2, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelIP,
				Code:      message.StackOptionCodeHappyEyeball,
				Data: &message.HappyEyeballOptionData{
					Availability: true,
				},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 2, 1, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelIP,
				Code:      message.StackOptionCodeHappyEyeball,
				Data: &message.HappyEyeballOptionData{
					Availability: false,
				},
			},
		})
	stackOptionDataTest(t,
		&message.HappyEyeballOptionData{
			Availability: false,
		}, false, true)
}

func TestTTLOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 3, 56, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelIP,
				Code:      message.StackOptionCodeTTL,
				Data: &message.TTLOptionData{
					TTL: 56,
				},
			},
		})
	stackOptionDataTest(t,
		&message.TTLOptionData{
			TTL: 77,
		}, byte(77), byte(34))
}

func TestNoFragmentationOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 4, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelIP,
				Code:      message.StackOptionCodeNoFragment,
				Data: &message.NoFragmentationOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&message.NoFragmentationOptionData{
			Availability: false,
		}, false, true)
}

func TestTFOOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 1, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelTCP,
				Code:      message.StackOptionCodeTFO,
				Data: &message.TFOOptionData{
					PayloadSize: 512,
				},
			},
		})
	stackOptionDataTest(t,
		&message.TFOOptionData{
			PayloadSize: 512,
		}, uint16(512), uint16(1111))
}
func TestMultipathOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 2, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelTCP,
				Code:      message.StackOptionCodeMultipath,
				Data: &message.MultipathOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&message.MultipathOptionData{
			Availability: true,
		}, true, false)
}

func TestBacklogOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 3, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelTCP,
				Code:      message.StackOptionCodeBacklog,
				Data: &message.BacklogOptionData{
					Backlog: 512,
				},
			},
		})
	stackOptionDataTest(t,
		&message.BacklogOptionData{
			Backlog: 512,
		}, uint16(512), uint16(1111))
}

func TestUDPErrorOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 5), 1, 2, 0,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelUDP,
				Code:      message.StackOptionCodeUDPError,
				Data: &message.UDPErrorOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&message.UDPErrorOptionData{
			Availability: false,
		}, false, true)
}

func TestPortParityOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 5), 2, 1, 2,
		}, message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     message.StackOptionLevelUDP,
				Code:      message.StackOptionCodePortParity,
				Data: &message.PortParityOptionData{
					Parity:  message.StackPortParityOptionParityEven,
					Reserve: true,
				},
			},
		})
	stackOptionDataTest(t,
		&message.PortParityOptionData{
			Parity:  message.StackPortParityOptionParityOdd,
			Reserve: false,
		},
		message.PortParityOptionData{
			Parity:  message.StackPortParityOptionParityOdd,
			Reserve: false,
		},
		message.PortParityOptionData{
			Parity:  message.StackPortParityOptionParityEven,
			Reserve: true,
		})
}
