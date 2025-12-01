// Package scheduler executes jobs in the future, at (or after) some scheduled time.
package scheduler

import (
	"container/heap"
	"time"
)

type job struct {
	at   time.Time
	task func()
}

// Schedule is the main interface for the scheduler
type Schedule struct {
	incoming chan job
	jobs     *jobHeap
	done     chan struct{}
}

// New sets up a schedule and starts running it.
func New() *Schedule {
	s := &Schedule{
		incoming: make(chan job),
		jobs:     new(jobHeap),
		done:     make(chan struct{}),
	}

	go s.loop()

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

// Stop running this schedule. No more jobs will run.
func (s *Schedule) Stop() {
	s.done <- struct{}{}
	close(s.done)
}

// loop is run in a goroutine, scheduling and running jobs, until Stop is called.
func (s *Schedule) loop() {
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
		case <-s.done:
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
