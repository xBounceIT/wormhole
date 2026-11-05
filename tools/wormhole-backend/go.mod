module github.com/xBounceIT/wormhole/tools/wormhole-backend

go 1.25.0

require (
	github.com/cloudsoda/go-smb2 v0.0.0-20260918041005-0c5d69b69701
	github.com/kward/go-vnc v0.0.0-20260515191714-83d72ad87d5f
	github.com/modelcontextprotocol/go-sdk v1.7.0
	github.com/pkg/sftp v1.13.9
	github.com/stretchr/testify v1.11.1
	github.com/xBounceIT/wormhole/tools/internal/sshauth v0.0.0
	github.com/zalando/go-keyring v0.2.8
	go.bug.st/serial v1.8.0
	golang.org/x/text v0.37.0
	modernc.org/sqlite v1.56.0
)

replace github.com/xBounceIT/wormhole/tools/internal/sshauth => ../internal/sshauth

// Required atomic no-replace rename and cancellation-safe handle cleanup.
replace github.com/cloudsoda/go-smb2 => ../../vendor/go-smb2

require (
	github.com/cloudsoda/sddl v0.0.0-20250224235906-926454e91efc // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.47.0
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
