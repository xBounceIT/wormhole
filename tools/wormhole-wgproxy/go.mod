module github.com/xBounceIT/wormhole/tools/wormhole-wgproxy

go 1.26.10

require (
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

// Local replace: the SOCKS5 surface is co-developed with the sidecars and lives next to
// them in this monorepo. The replace directive resolves the import to the sibling
// directory at build time so neither module needs a public release.
replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun

// Pin gvisor to the same commit that wireguard-go tests against. Upstream gvisor's
// `master` ships a `pkg/tcpip/stack/bridge_test.go` whose `package bridge_test` clause
// doesn't satisfy Go's package-per-directory rule for the parent `package stack`, so
// `go build` against it fails outside the gvisor team's bazel build. Holding gvisor at
// wireguard-go's tested version avoids that breakage without giving up the wireguard-go
// refresh. Revisit when gvisor upstream renames the test package or wireguard-go pins
// a newer version.
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
