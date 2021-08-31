package server

import (
	"github.com/studentmain/socks6/message"
)

type StackOptionInfo map[int]interface{}

func getStackOptions(options message.OptionSet, clientLeg bool) []message.Option {
	return options.GetKindF(message.OptionKindStack, func(o message.Option) bool {
		return o.Data.(message.BaseStackOptionData).RemoteLeg
	})
}
func GetStackOptionInfo(ops message.OptionSet, clientLeg bool) StackOptionInfo {
	rso := StackOptionInfo{}
	o := getStackOptions(ops, false)
	rso.AddMany(o)
	return rso
}
func (s *StackOptionInfo) Add(d message.BaseStackOptionData) {
	id := message.StackOptionID(d.Level, d.Code)
	dt := d.Data.(message.StackOptionData).GetData()
	(map[int]interface{})(*s)[id] = dt
}
func (s *StackOptionInfo) AddMany(d []message.Option) {
	for _, v := range d {
		rsod := v.Data.(message.BaseStackOptionData)
		s.Add(rsod)
	}
}

func (s StackOptionInfo) GetOptions(clientLeg bool, remoteLeg bool) []message.Option {
	r := []message.Option{}
	for id, dt := range s {
		var sod message.StackOptionData
		switch id {
		case message.StackOptionIPTOS:
			sod = &message.TOSOptionData{}
		case message.StackOptionIPHappyEyeball:
			sod = &message.HappyEyeballOptionData{}
		case message.StackOptionIPTTL:
			sod = &message.TTLOptionData{}
		case message.StackOptionIPNoFragment:
			sod = &message.NoFragmentationOptionData{}
		case message.StackOptionTCPMultipath:
			sod = &message.MultipathOptionData{}
		case message.StackOptionTCPTFO:
			sod = &message.TFOOptionData{}
		case message.StackOptionUDPUDPError:
			sod = &message.UDPErrorOptionData{}
		case message.StackOptionUDPPortParity:
			sod = &message.PortParityOptionData{}
		}
		sod.SetData(dt)
		lv, code := message.SplitStackOptionID(id)
		op := message.Option{
			Kind: message.OptionKindStack,
			Data: message.BaseStackOptionData{
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
