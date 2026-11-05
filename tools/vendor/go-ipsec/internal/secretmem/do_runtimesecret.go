//go:build goexperiment.runtimesecret

package secretmem

import "runtime/secret"

// Do invokes f under runtime/secret.Do: registers and stack used by f are
// erased before Do returns, and heap allocations made inside f are erased as
// soon as the garbage collector finds them unreachable.
func Do(f func()) { secret.Do(f) }
