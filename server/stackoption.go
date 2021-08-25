package server

import (
	"github.com/studentmain/socks6"
)

type StackOptionInfo map[int]interface{}

func getStackOptions(options socks6.OptionSet, clientLeg bool) []socks6.Option {
	return options.GetKindF(socks6.OptionKindStack, func(o socks6.Option) bool {
		return o.Data.(socks6.RawStackOptionData).RemoteLeg
	})
}
func GetStackOptionInfo(ops socks6.OptionSet, clientLeg bool) StackOptionInfo {
	rso := StackOptionInfo{}
	o := getStackOptions(ops, false)
	rso.AddMany(o)
	return rso
}
func (s *StackOptionInfo) Add(d socks6.RawStackOptionData) {
	id := socks6.StackOptionID(d.Level, d.Code)
	dt := d.Data.(socks6.StackOptionData).GetData()
	(map[int]interface{})(*s)[id] = dt
}
func (s *StackOptionInfo) AddMany(d []socks6.Option) {
	for _, v := range d {
		rsod := v.Data.(socks6.RawStackOptionData)
		s.Add(rsod)
	}
}

func (s StackOptionInfo) GetOptions(clientLeg bool, remoteLeg bool) []socks6.Option {
	r := []socks6.Option{}
	for id, dt := range s {
		var sod socks6.StackOptionData
		switch id {
		case socks6.StackOptionIPTOS:
			sod = &socks6.TOSOptionData{}
		case socks6.StackOptionIPHappyEyeball:
			sod = &socks6.HappyEyeballOptionData{}
		case socks6.StackOptionIPTTL:
			sod = &socks6.TTLOptionData{}
		case socks6.StackOptionIPNoFragment:
			sod = &socks6.NoFragmentationOptionData{}
		case socks6.StackOptionTCPMultipath:
			sod = &socks6.MultipathOptionData{}
		case socks6.StackOptionTCPTFO:
			sod = &socks6.TFOOptionData{}
		case socks6.StackOptionUDPUDPError:
			sod = &socks6.UDPErrorOptionData{}
		case socks6.StackOptionUDPPortParity:
			sod = &socks6.PortParityOptionData{}
		}
		sod.SetData(dt)
		lv, code := socks6.SplitStackOptionID(id)
		op := socks6.Option{
			Kind: socks6.OptionKindStack,
			Data: socks6.RawStackOptionData{
				Level:     lv,
				Code:      code,
				ClientLeg: clientLeg,
				RemoteLeg: remoteLeg,
				Data:      sod,
			},
		}
		r = append(r, op)
	}
	return r
}
