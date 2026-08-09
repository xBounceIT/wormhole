package main

import (
	"bytes"
	"sync"
)

// synchronizedBuffer lets asynchronous protocol tests inspect an output stream without racing
// the goroutine that is publishing the next event.
type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) Read(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Read(value)
}

func (buffer *synchronizedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func (buffer *synchronizedBuffer) Len() int {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Len()
}
