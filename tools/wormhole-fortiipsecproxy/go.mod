module github.com/xBounceIT/wormhole/tools/wormhole-fortiipsecproxy

go 1.26.10

require (
	github.com/n0madic/go-ipsec v0.0.0-20261003044543-96f638aa680f
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/n0madic/go-tun2net v0.0.0-20260607101155-baecdf85b64d // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260603223238-3694902083d5 // indirect
	layeh.com/radius v0.0.0-20231213012653-1006025d24f8 // indirect
)

replace github.com/n0madic/go-ipsec => ../vendor/go-ipsec

replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun

// Keep the same tested netstack as the other userspace VPN sidecars.
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
