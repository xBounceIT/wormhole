module github.com/xBounceIT/wormhole/tools/wormhole-ciscoproxy

go 1.25.0

require (
	github.com/pquerna/otp v1.5.0
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	golang.org/x/net v0.55.0
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/boombuler/barcode v1.1.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

// Local replace: the SOCKS5 surface is co-developed with the sidecars and lives next to
// them in this monorepo (mirrors wgproxy/ovpnproxy). The replace directive resolves the
// import to the sibling directory at build time so neither module needs a public release.
replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun

// Pin gvisor to wireguard-go's tested commit. See ../wormhole-wgproxy/go.mod for the
// reason — gvisor's `master` `pkg/tcpip/stack/bridge_test.go` doesn't satisfy Go's
// package-per-directory rule and breaks `go build` outside their bazel setup.
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
