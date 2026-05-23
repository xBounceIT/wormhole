module github.com/xBounceIT/wormhole/tools/wormhole-wgproxy

go 1.24.0

require (
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
)

// Local replace: the SOCKS5 surface is co-developed with the sidecars and lives next to
// them in this monorepo. The replace directive resolves the import to the sibling
// directory at build time so neither module needs a public release.
replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun
