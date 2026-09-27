package scan

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottleConcurrent(t *testing.T) {
	deliver := Throttle(time.Hour)
	var delivered atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if deliver(Progress{Phase: "scanning", Done: 1, Total: 10}) {
					delivered.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := delivered.Load(); n != 1 {
		t.Errorf("delivered %d updates within one interval, want 1", n)
	}
	if !deliver(Progress{Phase: "scanning", Done: 10, Total: 10}) || !deliver(Progress{Phase: "identifying"}) {
		t.Error("final count and phase changes must always be delivered")
	}
}
