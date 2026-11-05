//go:build !goexperiment.runtimesecret

package secretmem

// Do invokes f directly: without GOEXPERIMENT=runtimesecret there is no
// runtime support for guaranteed erasure.
func Do(f func()) { f() }
