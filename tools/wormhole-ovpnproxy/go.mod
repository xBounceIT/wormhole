module github.com/xBounceIT/wormhole/tools/wormhole-ovpnproxy

go 1.22

require (
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
)

// Local replace: share the SOCKS5 surface with wormhole-wgproxy so the two sidecars don't
// drift on protocol handling. See ../wormhole-wgproxy/go.mod for the matching directive.
replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun
