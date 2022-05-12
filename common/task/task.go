// sorry but i once was a .net programmer
package task

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type TaskStatus int

const (
	Created              TaskStatus = iota
	WaitingForActivation            // unused
	WaitingToRun
	Running
	WaitingForChildrenToComplete // unused
	RanToCompletion
	Canceled // broken
	Faulted
)

type Task[T any] struct {
	ct     context.Context
	once   sync.Once
	wg     sync.WaitGroup
	val    T
	fn     func() T
	panic  AggregateError
	status TaskStatus
}

func NewTask[T any](f func() T) Task[T] {
	return NewTaskContext(context.Background(), f)
}
func NewTaskContext[T any](ctx context.Context, f func() T) Task[T] {
	t := Task[T]{
		ct:     ctx,
		once:   sync.Once{},
		wg:     sync.WaitGroup{},
		fn:     f,
		status: Created,
	}
	return t
}

func (t Task[T]) Wait() (T, error) {
	return t.WaitContext(context.Background())
}

func (t Task[T]) WaitTimeout(tm time.Duration) (T, error) {
	c, cancel := context.WithTimeout(context.Background(), tm)
	defer cancel()

	return t.WaitContext(c)
}

func (t Task[T]) WaitContext(ctx context.Context) (T, error) {
	if t.IsCompleted() {
		return t.val, t.panic
	}
	ch := make(chan struct{})
	go func() {
		t.wg.Wait()
		ch <- struct{}{}
	}()
	select {
	case <-ch:
		return t.val, t.panic
	case <-ctx.Done():
		return t.val, ctx.Err()
	}
}

func (t Task[T]) Start() {
	t.once.Do(func() {
		t.status = WaitingToRun
		defer func() {
			if err := recover(); err != nil {
				t.panic = AggregateError{
					InnerError: err,
				}
				t.status = Faulted
			}
		}()

		select {
		case <-t.ct.Done():
			t.panic = AggregateError{t.ct.Err()}
			t.status = Canceled
		default:
			t.status = Running
			t.val = t.fn()
			t.status = RanToCompletion
		}
		t.wg.Done()
	})
}

func Run[T any](f func() T) Task[T] {
	return RunContext(context.Background(), f)
}

func RunContext[T any](ctx context.Context, f func() T) Task[T] {
	t := NewTaskContext(ctx, f)
	t.Start()
	return t
}

func (t Task[T]) Status() TaskStatus {
	return t.status
}

func (t Task[T]) IsCanceled() bool {
	return t.status == Canceled
}
func (t Task[T]) IsCompleted() bool {
	return t.status >= 5
}
func (t Task[T]) IsCompletedSuccessfully() bool {
	return t.status == RanToCompletion
}
func (t Task[T]) IsFaulted() bool {
	return t.status == Faulted
}

func (t Task[T]) Exception() error {
	return t.panic
}
func (t Task[T]) Result() T {
	return t.val
}

func Delay(t time.Duration) {
	c, cancel := context.WithCancel(context.Background())
	defer cancel()
	DelayContext(c, t)
}
func DelayContext(ctx context.Context, t time.Duration) {
	select {
	case <-time.After(t):
	case <-ctx.Done():
	}
}
func FromResult[T any](t T) Task[T] {
	return Run(func() T {
		return t
	})
}
func FromCanceled[T any](t T) Task[T] {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return RunContext(ctx, func() T {
		return t
	})
}
func FromException[T any](e error) Task[T] {
	return Run(func() T {
		panic(e)
	})
}

func WaitAny[T any](t ...Task[T]) int {
	return WaitAnyContext(context.Background(), t...)
}
func WaitAnyTimeout[T any](tm time.Duration, t ...Task[T]) int {
	c, cancel := context.WithTimeout(context.Background(), tm)
	defer cancel()
	return WaitAnyContext(c, t...)
}
func WaitAnyContext[T any](ctx context.Context, t ...Task[T]) int {
	ch := make(chan int)
	for i := 0; i < len(t); i++ {
		if t[i].IsCompleted() {
			return i
		} else {
			go func() {
				defer func() {
					recover()
				}()
				t[i].wg.Wait()
				ch <- i
				close(ch)
			}()
		}
	}
	select {
	case idx := <-ch:
		return idx
	case <-ctx.Done():
		return -1
	}
}

func WaitAll[T any](t ...Task[T]) {
	WaitAllContext(context.Background(), t...)
}
func WaitAllTimeout[T any](tm time.Duration, t ...Task[T]) bool {
	c, cancel := context.WithTimeout(context.Background(), tm)
	defer cancel()
	return WaitAllContext(c, t...)
}
func WaitAllContext[T any](ctx context.Context, t ...Task[T]) bool {
	ch := make(chan int, len(t))
	for i := 0; i < len(t); i++ {
		if t[i].IsCompleted() {
			ch <- i
		} else {
			go func() {
				defer func() {
					recover()
				}()
				t[i].wg.Wait()
				ch <- i
			}()
		}
	}
	for i := 0; i < len(t); i++ {
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

type AggregateError struct {
	InnerError any
}

var _ error = AggregateError{}

func (e AggregateError) Error() string {
	return fmt.Sprint("goroutine failed", e.InnerError)
}

func (e AggregateError) Is(e2 error) bool {
	if ee, ok := e.InnerError.(error); ok {
		return errors.Is(ee, e2)
	}
	return false
}

func (e AggregateError) Unwrap() error {
	if ee, ok := e.InnerError.(error); ok {
		return ee
	}
	return nil
}
