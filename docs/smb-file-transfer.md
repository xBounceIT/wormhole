# SMB file transfer

Choose **SMB** in Quick Connect or the shared connection editor. Enter
`smb://server/share`, `server/share`, or `\\server\share`. An optional folder
such as `smb://server/share/projects` selects the initial directory. Port 445
is the default; specify another port in the Port field or the SMB URL.
An empty Port field inherits applicable folder defaults before using 445.
UNC and plain paths preserve literal `#` and `%` characters; SMB URLs use
normal percent encoding.

The tab contains the same local/remote browser, directory tree, transfer queue,
conflict prompts, file operations and editor workflow used by SFTP. SMB
credentials accept a username and password with an optional domain. For inline
credentials use `DOMAIN\user` or `user@example.com`. Saved SMB password
profiles and Bitwarden credentials can also be selected or inherited from a
folder. Duplicating a tab opens an independent SMB session.

The portable Go backend negotiates SMB2/3 with NTLMv2 and requires message
signing. SMB1, anonymous access and Kerberos are not supported. Access is
restricted to the selected share; symbolic links and reparse points are
rejected. Server ACLs govern permissions: the browser does not map POSIX chmod
to SMB ACL changes. Credentials embedded in URLs are rejected.

VPN routes follow the existing tunnel lease lifecycle. SMB connects through
the acquired SOCKS route and does not fall back to a direct connection if it
fails. Closing the tab cancels its file operations, closes TCP and releases
the route. No operating-system share mount or credential file is created.
Cancelled operations close native file handles using a separate bounded
cleanup context. Failed handle cleanup retires the connection. Directory,
path metadata and path mutation operations have a 30-second deadline.
If cancellation leaves the result of a native open or short path operation
unknown, the connection is retired so the server can release its handles.

The existing transfer engine is reused through an in-memory adapter in Go;
the network connection uses SMB, with no SSH server or listener involved.
Backup/import preserves the SMB protocol and SMB credential references.
Unapproved replacements use the server's atomic no-replace rename; approved
overwrites use a separate replacement operation. A versioned compatibility
patch is documented in `vendor/go-smb2/WORMHOLE.md`.

Automated verification uses the real file-browser/transfer bridge with an
isolated test filesystem, plus credential and address validation and failed
native handshakes. Run `npm run test:smb`, `npm run test:quick-connect-state`,
`npm run test:sftp-state`, static checks, and `go test ./...` in
`tools/wormhole-backend`. Native authentication, server ACL behavior and real
VPN interoperability still require testing against an SMB server.
