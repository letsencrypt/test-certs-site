package scheduler

// jobHeap implements a heap sorted by job.at
// This is nearly verbatim taken from the container/heap example.
// Hopefully some day it can be replaced by a generic heap.
type jobHeap []job

func (h *jobHeap) Len() int {
	return len(*h)
}

func (h *jobHeap) Less(i, j int) bool {
	return (*h)[i].at.Before((*h)[j].at)
}

func (h *jobHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

func (h *jobHeap) Push(x any) {
	typed, ok := x.(job)
	if !ok {
		// Should be unreachable: heap.Push is only called with type job
		panic("incorrect type pushed to job heap")
	}
	*h = append(*h, typed)
}

func (h *jobHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]

	return x
}
