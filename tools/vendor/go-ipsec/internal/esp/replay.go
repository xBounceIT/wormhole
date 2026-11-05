// Package esp implements the userspace ESP data plane: the AES-CBC +
// HMAC-SHA2-256-128 transform (RFC 4303, tunnel mode) and an RFC 6479 anti-
// replay window. No reusable userspace Go ESP transform exists, so this is
// hand-rolled on the standard library.
package esp

import "sync"

// ReplayWindow is a sliding anti-replay window over 32-bit ESP sequence numbers
// (RFC 4303 §3.4.3 / RFC 6479). It rejects sequence 0, replays, and packets
// older than the window. It is safe for concurrent use.
type ReplayWindow struct {
	mu   sync.Mutex
	size uint32
	last uint32   // highest accepted sequence number
	bits []uint64 // bit o represents sequence (last - o); bit 0 == last
}

// MaxReplayWindow caps the anti-replay window size (in packets). A window far
// larger than this serves no purpose, and a pathological value would overflow the
// 32-bit word-count arithmetic (yielding a zero-length bitmap that panics on the
// first packet) or allocate unbounded memory, so NewReplayWindow clamps to it.
// 2^20 bits is a 128 KiB bitmap — orders of magnitude beyond any useful window.
const MaxReplayWindow uint32 = 1 << 20

// NewReplayWindow returns a window of the given size (rounded up to a multiple
// of 64; a zero or tiny size is bumped to 64, and a size above MaxReplayWindow is
// clamped to it).
func NewReplayWindow(size uint32) *ReplayWindow {
	if size < 64 {
		size = 64
	}
	if size > MaxReplayWindow {
		size = MaxReplayWindow
	}
	// 64-bit arithmetic so size+63 cannot wrap a uint32 near math.MaxUint32.
	words := (uint64(size) + 63) / 64
	return &ReplayWindow{size: uint32(words * 64), bits: make([]uint64, words)}
}

// Accept reports whether seq is acceptable and, if so, records it. It must be
// called after the ICV has been verified (RFC 4303 §3.4.3).
func (w *ReplayWindow) Accept(seq uint32) bool {
	if seq == 0 {
		return false // sequence 0 is never valid
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	switch {
	case seq > w.last:
		shiftUp(w.bits, uint(seq-w.last))
		w.last = seq
		w.setBit(0)
		return true
	case seq == w.last:
		return false // replay of the highest
	default:
		offset := w.last - seq
		if offset >= w.size {
			return false // older than the window
		}
		if w.getBit(offset) {
			return false // already seen
		}
		w.setBit(offset)
		return true
	}
}

func (w *ReplayWindow) setBit(offset uint32) {
	w.bits[offset/64] |= 1 << (offset % 64)
}

func (w *ReplayWindow) getBit(offset uint32) bool {
	return w.bits[offset/64]&(1<<(offset%64)) != 0
}

// shiftUp shifts the bitmap toward higher offsets by n bits (offset 0 is the
// lowest bit of word 0), zeroing the vacated low bits.
func shiftUp(b []uint64, n uint) {
	if n == 0 {
		return
	}
	words := int(n / 64)
	bits := n % 64
	if words >= len(b) {
		for i := range b {
			b[i] = 0
		}
		return
	}
	if bits == 0 {
		copy(b[words:], b[:len(b)-words])
	} else {
		for i := len(b) - 1; i > words; i-- {
			b[i] = (b[i-words] << bits) | (b[i-words-1] >> (64 - bits))
		}
		b[words] = b[0] << bits
	}
	for i := range words {
		b[i] = 0
	}
}
