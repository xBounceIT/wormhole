# Local vault browser ownership

Saved and unsaved HTTP/HTTPS connections use the authenticated Go vault owner.
The ordinary renderer sends public metadata: a canonical browser session ID,
an attempt number, and either a saved node ID or an exact Quick target. The
target contains protocol, address, optional port, tunnel selection and certificate
policy. It cannot contain credentials, cookies, private keys or recipient fields.
The native plan and proxy endpoint have no general renderer IPC endpoint.

`VaultWebIpc` reserves the document and browser before authorization. Close,
reload, renderer loss and global shutdown cancel that reservation and join an
opening still waiting for authorization or native registration. A stale cleanup
cannot close a replacement admission. Failed retirement keeps the browser ID
reserved until an explicit retry confirms cleanup.

Go parses a pasted URL with the existing browser rules. The selected protocol
and explicit port retain their existing precedence; IPv6 and escaped paths are
handled by the same normalizers. Query and fragment context stays in the
temporary target. Saved plans continue to omit it. Go marks only an owner-scoped
temporary plan as temporary, and the client, host and browser coordinator verify
that distinction. A Quick target is never a fabricated saved row or revision.
Its lease captures the original native client, workspace, session and epoch.
Shared Quick admission remains refused until the audited server flow exists.

`VaultWebConnections` prepares one target and, when needed, one native route for
the whole browser. Every sibling tab uses the same isolated Chromium partition
and route. Opening or closing one tab does not register or retire another target.
Before creating a view, the coordinator authenticates the native plan and
rechecks target URL, certificate policy and exact route revisions after the VPN
starts. Main applies direct or SOCKS policy before navigation. A route failure
closes the browser without a direct fallback.

Retirement has two phases. Native route shutdown runs alongside forced view
destruction and profile cleanup. Profile storage, cookies, cache and connections
are cleared only after running views have closed. Once both route and profile
retirement are confirmed, the owner releases the temporary target. Failed view
destruction or profile cleanup retains the native target and browser reservation;
the next explicit close can retry. The browser token captures the owning
document, allowing cleanup after its BrowserWindow has already been destroyed.

Tests exercise the actual App request, main IPC, coordinator, real Go vault RPC
and real Chromium browser lifecycle. They cover direct and routed saved/Quick
connections, URL context, native scope/release checks, unchanged catalogs,
shared tabs, route loss, owner reload/destruction, late authorization/admission
and failed cleanup followed by a confirmed retry. Native network fixtures are
controlled local servers and proxies; they do not establish interoperability
with a user's remote appliance or VPN provider.

The native Bitwarden/SSO adapter remains unfinished. Vault browser startup
continues to skip the legacy extension store.
