# Wormhole Windows credential reader

This helper is built only for Windows and reads the legacy generic credentials
written by the WinUI application. The legacy C# Credential Manager stores
passwords as UTF-16LE bytes in `CredentialBlob`; the helper decodes those bytes
and emits a JSON array on stdout for the Electron main process.

Build one architecture from this directory with:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64' # or arm64
go build -trimpath -ldflags '-s -w' -o wormhole-credential-reader.exe .
```

The process never writes credentials to disk and never logs credential values.
