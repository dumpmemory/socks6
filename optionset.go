package socks6

import "io"

type OptionSet struct {
	perKind map[OptionKind][]Option
	list    []Option

	cached bool
	cache  []byte
}

func NewOptions() OptionSet {
	return OptionSet{
		perKind: map[OptionKind][]Option{},
		list:    []Option{},
		cached:  false,
	}
}

func parseOptions(b []byte) (OptionSet, int, error) {
	ops := NewOptions()
	totalLen := 0
	remain := b
	for len(remain) >= 4 {
		op, err := ParseOption(remain)
		if err != nil {
			return ops, 0, addExpectedLen(err, totalLen)
		}
		remain = remain[op.Length:]
		totalLen += int(op.Length)
		ops.Add(op)
	}
	return ops, totalLen, nil
}
func parseOptionsFrom(b io.Reader, limit int) (OptionSet, error) {
	ops := NewOptions()
	totalLen := 0
	for totalLen < limit {
		op, err := ParseOptionFrom(b)
		if err != nil {
			return ops, addExpectedLen(err, totalLen)
		}
		totalLen += int(op.Length)
		ops.Add(op)
	}
	return ops, nil
}
func (s *OptionSet) Add(o Option) {
	arr, ok := s.perKind[o.Kind]
	if !ok {
		arr = make([]Option, 0)
	}
	s.perKind[o.Kind] = append(arr, o)
	s.list = append(s.list, o)
	s.cached = false
}
func (s *OptionSet) AddMany(o []Option) {
	for _, v := range o {
		s.Add(v)
	}
}
func (s *OptionSet) Marshal() []byte {
	if s.cached {
		return s.cache
	}
	b := []byte{}
	for _, op := range s.list {
		opb := op.Marshal()
		b = append(b, opb...)
	}
	s.cache = b
	return b
}

func (s *OptionSet) get(kind OptionKind) (Option, bool) {
	arr, ok := s.perKind[kind]
	if !ok {
		return Option{}, false
	}
	if len(arr) < 1 {
		return Option{}, false
	}
	return arr[0], true
}
func (s *OptionSet) GetData(kind OptionKind) (OptionData, bool) {
	op, ok := s.get(kind)
	return op.Data, ok
}
func (s *OptionSet) GetKind(kind OptionKind) []Option {
	arr, ok := s.perKind[kind]
	if !ok {
		return []Option{}
	}
	return arr
}
func (s *OptionSet) GetDataF(kind OptionKind, fn func(Option) bool) (OptionData, bool) {
	ops := s.GetKind(kind)

	for _, op := range ops {
		if fn(op) {
			return op.Data, true
		}
	}
	return nil, false
}
func (s *OptionSet) GetKindF(kind OptionKind, fn func(Option) bool) []Option {
	ops := s.GetKind(kind)
	r := []Option{}
	for _, op := range ops {
		if fn(op) {
			r = append(r, op)
		}
	}
	return r
}
