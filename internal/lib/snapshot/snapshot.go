// Package snapshot provides single-writer, many-reader state publication.
// Actors own their mutable state exclusively and publish immutable
// snapshots; hot paths (request handling) read the current snapshot without
// locks, so no mutexes are needed anywhere (actor-model discipline).
package snapshot

import "sync/atomic"

type Store[T any] struct {
	value atomic.Pointer[T]
}

func New[T any](initial T) *Store[T] {
	store := &Store[T]{}
	store.value.Store(&initial)

	return store
}

func (s *Store[T]) Load() T {
	return *s.value.Load()
}

func (s *Store[T]) Publish(value T) {
	s.value.Store(&value)
}
