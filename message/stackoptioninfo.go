package message

type StackOptionInfo map[int]interface{}

func getStackOptions(options *OptionSet, clientLeg bool) []Option {
	fn := func(o Option) bool {
		return o.Data.(BaseStackOptionData).RemoteLeg
	}

	if clientLeg {
		fn = func(o Option) bool {
			return o.Data.(BaseStackOptionData).ClientLeg
		}
	}
	return options.GetKindF(OptionKindStack, fn)
}
func GetStackOptionInfo(ops *OptionSet, clientLeg bool) StackOptionInfo {
	rso := StackOptionInfo{}
	o := getStackOptions(ops, false)
	rso.AddMany(o)
	return rso
}
func (s *StackOptionInfo) Add(d BaseStackOptionData) {
	id := StackOptionID(d.Level, d.Code)
	dt := d.Data.GetData()
	(map[int]interface{})(*s)[id] = dt
}
func (s *StackOptionInfo) AddMany(d []Option) {
	for _, v := range d {
		rsod := v.Data.(BaseStackOptionData)
		s.Add(rsod)
	}
}
func (s *StackOptionInfo) Combine(s2 StackOptionInfo) {
	for k, v := range s2 {
		(*s)[k] = v
	}
}

func (s StackOptionInfo) Filter(s2 StackOptionInfo) StackOptionInfo {
	if len(s2) == 0 {
		return s
	}
	ret := StackOptionInfo{}
	for k, op := range s {
		_, ok := s2[k]
		if ok {
			ret[k] = op
		}
	}
	return ret
}

func getOptionFromData(id int, data interface{}, clientLeg bool, remoteLeg bool) Option {
	var sod StackOptionData
	switch id {
	case StackOptionIPTOS:
		sod = &TOSOptionData{}
	case StackOptionIPHappyEyeball:
		sod = &HappyEyeballOptionData{}
	case StackOptionIPTTL:
		sod = &TTLOptionData{}
	case StackOptionIPNoFragment:
		sod = &NoFragmentationOptionData{}
	case StackOptionTCPMultipath:
		sod = &MultipathOptionData{}
	case StackOptionTCPTFO:
		sod = &TFOOptionData{}
	case StackOptionUDPUDPError:
		sod = &UDPErrorOptionData{}
	case StackOptionUDPPortParity:
		sod = &PortParityOptionData{}
	case StackOptionTCPBacklog:
		sod = &BacklogOptionData{}
	}
	sod.SetData(data)
	lv, code := SplitStackOptionID(id)
	op := Option{
		Kind: OptionKindStack,
		Data: BaseStackOptionData{
			Level:     lv,
			Code:      code,
			ClientLeg: clientLeg,
			RemoteLeg: remoteLeg,
			Data:      sod,
		},
	}
	return op
}

func (s StackOptionInfo) GetOptions(clientLeg bool, remoteLeg bool) []Option {
	r := []Option{}
	for id, dt := range s {
		op := getOptionFromData(id, dt, clientLeg, remoteLeg)
		r = append(r, op)
	}
	return r
}

func GetCombinedStackOptions(client StackOptionInfo, remote StackOptionInfo) []Option {
	keys := make([]int, 0, len(client)+len(remote))
	for k := range client {
		keys = append(keys, k)
	}
	for k := range remote {
		keys = append(keys, k)
	}

	ret := make([]Option, 0)
	for _, k := range keys {
		cval, cok := client[k]
		rval, rok := remote[k]
		var op Option
		if cok != rok || cval != rval {
			if cok {
				op = getOptionFromData(k, cval, true, false)
			}
			if rok {
				op = getOptionFromData(k, rval, false, true)
			}
		} else {
			op = getOptionFromData(k, cval, true, true)
		}
		ret = append(ret, op)
	}
	return ret
}
