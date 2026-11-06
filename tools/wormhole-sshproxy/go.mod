module github.com/xBounceIT/wormhole/tools/wormhole-sshproxy

go 1.26.10

require (
	github.com/xBounceIT/wormhole/tools/internal/sockstun v0.0.0
	github.com/xBounceIT/wormhole/tools/internal/sshauth v0.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
)

require golang.org/x/sys v0.49.0 // indirect

replace github.com/xBounceIT/wormhole/tools/internal/sockstun => ../internal/sockstun

replace github.com/xBounceIT/wormhole/tools/internal/sshauth => ../internal/sshauth
