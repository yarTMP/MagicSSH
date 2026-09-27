package scan

import (
	"sync/atomic"
	"time"
)

// Throttle limits progress updates to one per interval, but always lets phase
// changes and the final count through. The returned function is safe to call
// from many scan workers at once: the last delivery time is claimed with a
// compare-and-swap.
func Throttle(interval time.Duration) func(Progress) bool {
	var last atomic.Int64
	return func(p Progress) bool {
		now := time.Now().UnixNano()
		if p.Phase != "scanning" || p.Done == p.Total {
			last.Store(now)
			return true
		}
		prev := last.Load()
		return now-prev >= int64(interval) && last.CompareAndSwap(prev, now)
	}
}
