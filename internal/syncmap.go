package internal

import "sync"

type SyncMap[K comparable, V any] struct {
	sync.Map
}

func (s *SyncMap[K, V]) Load(key K) (value V, ok bool) {
	v, o := s.Map.Load(key)
	return v.(V), o
}

func (s *SyncMap[K, V]) Store(key K, value V) {
	s.Map.Store(key, value)
}

func (s *SyncMap[K, V]) Range(f func(key K, value V) bool) {
	s.Map.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}

func (s *SyncMap[K, V]) Delete(key K) {
	s.Map.Delete(key)
}
