package scheduler

import "container/heap"

// jobHeap implements a heap sorted by job.at
// This is nearly verbatim taken from the container/heap example.
// Hopefully some day it can be replaced by a generic heap.
type jobHeap []job

// jobHeap implements heap.Interface
var _ heap.Interface = (*jobHeap)(nil)

// Len is required for heap.Interface
func (h *jobHeap) Len() int {
	return len(*h)
}

// Less is required for heap.Interface
func (h *jobHeap) Less(i, j int) bool {
	return (*h)[i].at.Before((*h)[j].at)
}

// Swap is required for heap.Interface
func (h *jobHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

// Push is required for heap.Interface
func (h *jobHeap) Push(x any) {
	typed, ok := x.(job)
	if !ok {
		// Should be unreachable: heap.Push is only called with type job
		panic("incorrect type pushed to job heap")
	}
	*h = append(*h, typed)
}

// Pop is required for heap.Interface
func (h *jobHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]

	return x
}
