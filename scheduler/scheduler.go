// Package scheduler executes jobs in the future, at (or after) some scheduled time.
package scheduler

import (
	"container/heap"
	"context"
	"time"
)

type job struct {
	at   time.Time
	task func()
}

// Schedule is the main handle for the scheduler, returned from New()
type Schedule struct {
	incoming chan job
	jobs     *jobHeap
}

// New sets up a schedule and starts running it.
// The scheduler will stop running jobs once the context is canceled.
func New(ctx context.Context) *Schedule {
	s := &Schedule{
		incoming: make(chan job),
		jobs:     new(jobHeap),
	}

	go s.loop(ctx)

	return s
}

// RunAt schedules a task to be run at some time in the future.
func (s *Schedule) RunAt(at time.Time, task func()) {
	s.incoming <- job{task: task, at: at}
}

// RunIn schedules a task to be run after duration has passed.
func (s *Schedule) RunIn(in time.Duration, task func()) {
	s.RunAt(time.Now().Add(in), task)
}

// loop is run in a goroutine, scheduling and running jobs, until ctx is done.
func (s *Schedule) loop(ctx context.Context) {
	for {
		var next <-chan time.Time
		if len(*s.jobs) > 0 {
			next = time.After(time.Until((*s.jobs)[0].at))
		}
		select {
		case <-next:
			s.execute()
		case j := <-s.incoming:
			heap.Push(s.jobs, j)
		case <-ctx.Done():
			return
		}
	}
}

// execute any job whose time has come
func (s *Schedule) execute() {
	for len(*s.jobs) > 0 {
		if time.Now().Before((*s.jobs)[0].at) {
			// Heap minimum is in the future, so we are done for now
			return
		}

		r, ok := heap.Pop(s.jobs).(job)
		if !ok {
			// Should be unreachable: the underlying job heap only stores type job
			panic("incorrect type popped from job heap")
		}

		go r.task()
	}
}
