package message

import (
	"fmt"
	"io"
)

type OptionSet struct {
	perKind map[OptionKind][]Option
	list    []Option

	cached bool
	cache  []byte
}

func (s OptionSet) String() string {
	return fmt.Sprintf("OptionSet%+v", s.list)
}

func NewOptionSet() *OptionSet {
	return &OptionSet{
		perKind: map[OptionKind][]Option{},
		list:    []Option{},
		cached:  false,
	}
}

func ParseOptionSetFrom(b io.Reader, limit int) (*OptionSet, error) {
	ops := NewOptionSet()
	if limit > MaxOptionSize {
		return nil, ErrOptionTooLong
	}
	totalLen := 0
	for totalLen < limit {
		op, err := ParseOptionFrom(b)
		if err != nil {
			return nil, err
		}
		totalLen += int(op.Length)
		ops.Add(op)
	}
	return ops, nil
}
func (s *OptionSet) Add(o Option) {
	arr, ok := s.perKind[o.Kind]
	if !ok {
		arr = []Option{}
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
	s.cached = true
	return b
}
func (s *OptionSet) Len() int {
	return len(s.list)
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
