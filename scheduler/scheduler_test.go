package scheduler

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestScheduler(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		s := New()

		mu := sync.Mutex{}
		var data []int64
		wg := &sync.WaitGroup{}

		for _, num := range []int64{8, 11, 10, 3, 7, 4, 6, 9, -1, 5, 1, 12, 2} {
			wg.Add(1)
			s.RunIn(time.Duration(num)*time.Hour, func() error {
				mu.Lock()
				defer mu.Unlock()

				data = append(data, num)
				wg.Done()

				return nil
			})
		}

		wg.Wait()
		s.Stop()

		if !slices.Equal(data, []int64{-1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
			t.Fatal("List was incorrect, so tasks didn't run in expected order", data)
		}
	})
}
