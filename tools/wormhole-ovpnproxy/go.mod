module github.com/xBounceIT/wormhole/tools/wormhole-ovpnproxy

go 1.26.10

require (
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

// Local replace: share the SOCKS5 surface with wormhole-wgproxy so the two sidecars don't
// drift on protocol handling. See ../wormhole-wgproxy/go.mod for the matching directive.
replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun

// Pin gvisor to wireguard-go's tested commit. See ../wormhole-wgproxy/go.mod for the
// reason — gvisor's `master` `pkg/tcpip/stack/bridge_test.go` doesn't satisfy Go's
// package-per-directory rule and breaks `go build` outside their bazel setup.
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
