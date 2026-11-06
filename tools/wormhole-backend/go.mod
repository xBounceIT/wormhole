module github.com/xBounceIT/wormhole/tools/wormhole-backend

go 1.26.10

require (
	github.com/cloudsoda/go-smb2 v0.0.0-20261105190815-95be04a983b8
	github.com/kward/go-vnc v0.0.0-20260515191714-83d72ad87d5f
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/pkg/sftp v1.13.12
	github.com/stretchr/testify v1.12.1
	github.com/xBounceIT/wormhole/tools/internal/sshauth v0.0.0
	github.com/zalando/go-keyring v0.2.8
	go.bug.st/serial v1.8.0
	golang.org/x/text v0.43.0
	modernc.org/sqlite v1.61.1
)

replace github.com/xBounceIT/wormhole/tools/internal/sshauth => ../internal/sshauth

// Required atomic no-replace rename and cancellation-safe handle cleanup.
replace github.com/cloudsoda/go-smb2 => ../../vendor/go-smb2

require (
	github.com/cloudsoda/sddl v0.0.0-20261105185302-1c8f96799263 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/geoffgarside/ber v1.2.0 // indirect
	github.com/godbus/dbus/v5 v5.2.4 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/hashicorp/go-uuid v1.0.4 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.16.0 // indirect
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
