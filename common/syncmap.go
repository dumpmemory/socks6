package common

import (
	"sync"
)

type SyncMap[K comparable, V any] struct {
	m *sync.Map
}

func NewSyncMap[K comparable, V any]() SyncMap[K, V] {
	return SyncMap[K, V]{
		m: &sync.Map{},
	}
}

func (s *SyncMap[K, V]) Load(key K) (value V, ok bool) {
	v, o := s.m.Load(key)
	v2, _ := v.(V)
	return v2, o
}

func (s *SyncMap[K, V]) Store(key K, value V) {
	s.m.Store(key, value)
}

func (s *SyncMap[K, V]) Range(f func(key K, value V) bool) {
	s.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}

func (s *SyncMap[K, V]) Delete(key K) {
	s.m.Delete(key)
}
