package socks6_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/studentmain/socks6"
)

func TestStackOptionID(t *testing.T) {
	assert.Equal(t, 258, socks6.StackOptionID(1, 2))
	a, b := socks6.SplitStackOptionID(258)
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
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: true,
				RemoteLeg: false,
				Level:     6,
				Code:      10,
				Data: &socks6.RawOptionData{
					Data: []byte{0, 0},
				},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 6), 10, 0, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     6,
				Code:      10,
				Data: &socks6.RawOptionData{
					Data: []byte{0, 0},
				},
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, false, 6), 10, 0, 0,
		}, socks6.Option{})
}

func TestSetStackOptionDataParser(t *testing.T) {
	socks6.SetStackOptionDataParser(6, 1, func(b []byte) (socks6.StackOptionData, error) { return &socks6.TTLOptionData{TTL: 9}, nil })
	optionDataTest(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 6), 1, 9, 0,
	}, socks6.Option{
		Kind: socks6.OptionKindStack,
		Data: socks6.BaseStackOptionData{
			ClientLeg: false,
			RemoteLeg: true,
			Level:     6,
			Code:      1,
			Data: &socks6.TTLOptionData{
				TTL: 9,
			},
		},
	})
	socks6.SetStackOptionDataParser(6, 1, nil)
	optionDataTest(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 6), 1, 9, 0,
	}, socks6.Option{
		Kind: socks6.OptionKindStack,
		Data: socks6.BaseStackOptionData{
			ClientLeg: false,
			RemoteLeg: true,
			Level:     6,
			Code:      1,
			Data: &socks6.RawOptionData{
				Data: []byte{9, 0},
			},
		},
	})
}

func stackOptionDataTest(t *testing.T, obj socks6.StackOptionData, orig, new interface{}) {
	// serialize and deserialize are tested by optionDataTest
	assert.Equal(t, obj.GetData(), orig)
	obj.SetData(new)
	assert.Equal(t, obj.GetData(), new)
}

func TestRawOptionDataAsStackOptionData(t *testing.T) {
	stackOptionDataTest(t,
		&socks6.RawOptionData{
			Data: []byte{1},
		},
		[]byte{1}, []byte{1, 2, 3, 4, 5})
}

func TestTOSOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 1, 6, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelIP,
				Code:      socks6.StackOptionCodeTOS,
				Data: &socks6.TOSOptionData{
					TOS: 6,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.TOSOptionData{
			TOS: 9,
		}, byte(9), byte(15))
}

func TestHappyEyeballOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 2, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelIP,
				Code:      socks6.StackOptionCodeHappyEyeball,
				Data: &socks6.HappyEyeballOptionData{
					Availability: true,
				},
			},
		})
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 2, 1, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelIP,
				Code:      socks6.StackOptionCodeHappyEyeball,
				Data: &socks6.HappyEyeballOptionData{
					Availability: false,
				},
			},
		})
	optionDataTestProtocolPolice(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 2, 0, 0,
		}, socks6.Option{})
	stackOptionDataTest(t,
		&socks6.HappyEyeballOptionData{
			Availability: false,
		}, false, true)
}

func TestTTLOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 3, 56, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelIP,
				Code:      socks6.StackOptionCodeTTL,
				Data: &socks6.TTLOptionData{
					TTL: 56,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.TTLOptionData{
			TTL: 77,
		}, byte(77), byte(34))
}

func TestNoFragmentationOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 1), 4, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelIP,
				Code:      socks6.StackOptionCodeNoFragment,
				Data: &socks6.NoFragmentationOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.NoFragmentationOptionData{
			Availability: false,
		}, false, true)
}

func TestTFOOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 1, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelTCP,
				Code:      socks6.StackOptionCodeTFO,
				Data: &socks6.TFOOptionData{
					PayloadSize: 512,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.TFOOptionData{
			PayloadSize: 512,
		}, uint16(512), uint16(1111))
}
func TestMultipathOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 2, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelTCP,
				Code:      socks6.StackOptionCodeMultipath,
				Data: &socks6.MultipathOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.MultipathOptionData{
			Availability: true,
		}, true, false)
}

func TestBacklogOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 4), 3, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelTCP,
				Code:      socks6.StackOptionCodeBacklog,
				Data: &socks6.BacklogOptionData{
					Backlog: 512,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.BacklogOptionData{
			Backlog: 512,
		}, uint16(512), uint16(1111))
}

func TestUDPErrorOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 5), 1, 2, 0,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelUDP,
				Code:      socks6.StackOptionCodeUDPError,
				Data: &socks6.UDPErrorOptionData{
					Availability: true,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.UDPErrorOptionData{
			Availability: false,
		}, false, true)
}

func TestPortParityOptionData(t *testing.T) {
	optionDataTest(t,
		[]byte{
			0, 1, 0, 8,
			legLevel(false, true, 5), 2, 1, 2,
		}, socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.BaseStackOptionData{
				ClientLeg: false,
				RemoteLeg: true,
				Level:     socks6.StackOptionLevelUDP,
				Code:      socks6.StackOptionCodePortParity,
				Data: &socks6.PortParityOptionData{
					Parity:  socks6.StackPortParityOptionParityEven,
					Reserve: true,
				},
			},
		})
	stackOptionDataTest(t,
		&socks6.PortParityOptionData{
			Parity:  socks6.StackPortParityOptionParityOdd,
			Reserve: false,
		},
		socks6.PortParityOptionData{
			Parity:  socks6.StackPortParityOptionParityOdd,
			Reserve: false,
		},
		socks6.PortParityOptionData{
			Parity:  socks6.StackPortParityOptionParityEven,
			Reserve: true,
		})
	optionDataTestProtocolPolice(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 5), 2, 0, 0,
	}, socks6.Option{})
	optionDataTestProtocolPolice(t, []byte{
		0, 1, 0, 8,
		legLevel(false, true, 5), 2, 9, 1,
	}, socks6.Option{})
}
