// Package secretmem wraps key-material computations so their working memory
// (registers, stack, and heap allocations made inside the wrapped function) is
// erased once no longer needed. It is a thin seam over the experimental
// runtime/secret package: build with GOEXPERIMENT=runtimesecret (Go 1.26+;
// erasure is effective on linux/amd64 and linux/arm64, a direct call
// elsewhere) to activate it. The default build compiles Do to a plain call —
// Go's GC gives no reliable way to zero moving heap memory by hand, so a
// best-effort manual wipe is deliberately not attempted.
//
// Rule of thumb: allocate secrets INSIDE Do. An allocation made inside Do is
// tracked by the runtime and zeroed as soon as the GC finds it unreachable, so
// long-lived key material (IKE SK_*, ESP keys, the EAP MSK) allocated inside
// Do is erased automatically when its SA is dropped on rekey or teardown.
//
// Known limitation: caller-provided secrets that were allocated outside Do
// (Config.PSK, the EAP password string) are not tracked and live until the
// process exits.
package secretmem
