package main

import "sync"

// Bound pending input by bytes, rather than event count. Terminal applications
// can trigger many tiny DSR/DA replies in one output packet. Coalescing preserves
// their order without making a normal reply burst look like a stalled peer.
const sshInputQueueMaxBytes = 4 * sshInputMaxBytes

type sshInputQueue struct {
	mu     sync.Mutex
	data   []byte
	limit  int
	closed bool
	ready  chan struct{}
}

func newSSHInputQueue(limit int) *sshInputQueue {
	return &sshInputQueue{limit: limit, ready: make(chan struct{}, 1)}
}

func (queue *sshInputQueue) write(data []byte) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.closed {
		return errSSHSessionClosed
	}
	if len(data) > queue.limit-len(queue.data) {
		return errSSHInputFull
	}
	queue.data = append(queue.data, data...)
	select {
	case queue.ready <- struct{}{}:
	default:
	}
	return nil
}

func (queue *sshInputQueue) take() []byte {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	data := queue.data
	queue.data = nil
	return data
}

func (queue *sshInputQueue) size() int {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return len(queue.data)
}

func (queue *sshInputQueue) stop() {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.closed = true
	queue.data = nil
}
