package main

import "sync"

// boundedStderrBuilder drains every write, retaining only the latest diagnostics.
// A native VPN can emit long lines or more than the limit before readiness; neither
// must close its stderr pipe or discard the final failure in favor of startup noise.
type boundedStderrBuilder struct {
	mu    sync.Mutex
	limit int
	tail  []byte
}

func (b *boundedStderrBuilder) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 || len(p) == 0 {
		return len(p), nil
	}
	if b.tail == nil {
		b.tail = make([]byte, 0, b.limit)
	}
	if len(p) >= b.limit {
		b.tail = append(b.tail[:0], p[len(p)-b.limit:]...)
	} else {
		if overflow := len(b.tail) + len(p) - b.limit; overflow > 0 {
			b.tail = b.tail[:copy(b.tail, b.tail[overflow:])]
		}
		b.tail = append(b.tail, p...)
	}
	return len(p), nil
}

func (b *boundedStderrBuilder) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.tail)
}
