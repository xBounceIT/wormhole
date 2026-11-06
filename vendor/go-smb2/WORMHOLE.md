# Wormhole compatibility patch

Source: CloudSoda/go-smb2 `v0.0.0-20261105190815-95be04a983b8`.
`UPSTREAM.json` records the source version and SHA-256 hashes before patching.
The upstream license is preserved in `LICENSE`.

Local runtime changes are limited to `client.go`. The module manifests also use
Wormhole's Go security floor and refreshed dependency versions. `Share.RenameNoReplace` sends
`FileRenameInformation.ReplaceIfExists=0`, preventing collisions atomically.
Existing `Share.Rename` keeps its replacement behavior. `File.CloseContext`
allows bounded cleanup after an operation context has been cancelled, retaining
the original `Close` behavior for existing callers.

`wormhole_test.go` checks actual CREATE, SET_INFO and CLOSE requests against an
in-memory SMB peer, including cancellation and bounded cleanup. From
`tools/wormhole-backend`, run:

```powershell
go test github.com/cloudsoda/go-smb2 -run TestWormhole
```

Run in the backend module so tests use the same dependency versions as the
application. The unchanged third-party sources are excluded from application
coverage; the added native contracts and adapter have separate focused tests.
