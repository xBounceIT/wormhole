package secretmem

// Wipe overwrites b with zeros — the best-effort erasure long-lived secret
// copies get in the default build (Go's current GC does not move heap
// objects, so the backing array is reliably cleared; stray intermediate
// copies are out of reach and remain until process exit). With the
// runtime/secret experiment active a tracked allocation is erased again when
// freed; the double clear is harmless.
func Wipe(b []byte) { clear(b) }
