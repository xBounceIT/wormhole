# Protected RDP session transport

Saved local and shared RDP connections, including protected temporary accounts, use the authenticated Go vault through
main-owned IPC, preload and the existing desktop surface. Go resolves the saved
connection and seals credentials to an owned native process; ordinary Electron
and React receive only public events and opaque ciphertext. This completes the
saved-node RDP integration boundary, not the full #495 roadmap.

## Authority and credential ownership

`rdp-bundle`, `rdp-route-bundle`, `rdp-plan`, `rdp-manual-bundle` and
`rdp-manual-route-bundle` are native/main-only vault operations. Every
request is re-resolved inside its owner gate. The local owner holds its lock
through resolution, credential borrowing and sealing. Shared access uses the
existing audited admission, authenticated metadata/credential graph, durable
trust publication and current private-key gate. Settings and route policy are
checked before borrowing shared private keys. Frozen resolver Plan format 1 is
unchanged: a detached projection of the authenticated chain supplies the complete
RDP settings, and effective account/gateway decisions overlay that projection.
NULL inherits; explicit false, zero and empty values remain authoritative.

The payload supports saved and inline primary passwords, local credential
selection overrides, none, absent and explicit empty passwords, and a separate
saved gateway account. Shared overrides and unsupported credential providers are
refused. Same-credential gateway policy does not read an independent gateway
secret. When a primary password is supplied, the Go native execution profile
uses two explicit primary/gateway setters. Microsoft documents GatewayCredSharing
as single-prompt sharing, not programmatic password sharing. With no supplied
password, the native shared prompt remains available.

Source: [Microsoft GatewayCredSharing documentation](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclienttransportsettings2-gatewaycredsharing).

## Encrypted frame

The binary payload is at most 64 KiB. Byte 0 is version 1; byte 1 contains primary
and gateway password-presence bits. Six fields follow, each preceded by a
big-endian uint32 length: primary username, gateway username, gateway domain,
complete canonical public RDP settings JSON, primary password, gateway password.
Only password fields borrow the decoded mutable frame. The owner wipes that
frame and every owned password buffer. Absent and explicit empty are distinct.
Identity/settings/secret text is bounded and valid UTF-8; line breaks and NUL in
passwords are refused to preserve the supported native stdin contracts. Missing,
unknown, duplicate and noncanonical settings objects are rejected.

HPKE authenticates workspace, node, session, request, epoch, protocol and target.
The routed variant additionally binds the exact file/tunnel revision and loopback
endpoint. A changed tunnel revision is rejected. A display-name-only node edit
need not invalidate an otherwise identical route. No failure retries directly.
Routed RD Gateway and mandatory certificate-authentication level 1 remain refused
because the existing loopback forwarder cannot preserve those policies. The
Windows external-client preference is cleared on Unix, matching legacy platform
behavior. Windows external/AzureAD execution remains outside this sealed path.

## Protected temporary account

The local and shared RDP failure/disconnected surface offers **Enter credentials
securely**. Main first confirms retirement of the old attempt, creates a fresh
native recipient and opens the dedicated sandboxed `vault-rdp-credentials.html`
document. The normal renderer sends only `manualCredentials: true` with the saved
node/session identifiers and bounds. Username, domain and password stay in the
isolated document until encryption to Go. The document bridge exposes only
context, opaque submission, cancellation and content-protection capability.
It has a fresh nonpersistent partition, no network access and no general vault API.

`rdp-plan` authenticates public metadata without borrowing passwords. The document
clears all three inputs on submit; the sender consumes their mutable byte arrays
before its first asynchronous crypto operation. Cancellation clears the DOM,
consumes outstanding buffers and discards late crypto results. Main destroys the
document and positively confirms destruction before accepting its envelope. Lock,
parent reload/crash/close, navigation and a five-minute deadline cancel entry.
Linux reports that capture protection is unavailable.

The inner HPKE purpose is `wormhole/v1/rdp-manual-credentials`. Its context contains
14 length-prefixed UTF-8 fields in order: workspace, node, session, request,
protocol, host, decimal port, tunnel ID, decimal epoch, file ID, tunnel kind,
row revision, configuration revision and loopback endpoint. Direct requests use
empty values for the final five fields. The inner binary frame starts with version
1 and mandatory password-presence byte 1, followed by three big-endian uint32
length-prefixed fields: username, domain and password. Username is required;
explicit empty password is valid. Username/domain are at most 2048 UTF-8 bytes
and 513 Unicode code points each; password is at most 16384 bytes and 4096 code
points. A leading UTF-8 BOM is credential content and counts as a code point.
Invalid UTF-8, CR, LF and NUL are refused. Maximum inner ciphertext is
20510 bytes including the authentication tag.

Go re-resolves the current target, full options, gateway and route under the
existing owner/admission gate. The authorization frame is version 2, followed by
uint32 base-frame length, a canonical version-1 RDP options/gateway frame,
32 encapsulation bytes, uint32 inner-ciphertext length and the inner ciphertext.
The base has no primary username/domain/password or presence bit. This whole
frame is sealed by the vault to the native recipient and bounded to 64 KiB.
The manual-only `rdp-manual-sealed` process refuses a saved authorization frame;
only that process opens and overlays the inner primary account.

No saved primary role is decrypted during manual admission. An explicitly
selected independent gateway is borrowed through a gateway-only gate; it can
refer to the same credential ID as the saved primary without selecting the
primary role. Same-account gateway policy instead uses the temporary account.
The saved primary identity, including AzureAD, cannot force a temporary account
into the system client. Explicit external-client policy remains authoritative;
the native recipient also refuses an actual temporary AzureAD account on Windows.
A VPN lease authenticates the route independently of the saved primary identity;
the saved RDP path still refuses an unsupported external identity. Route failures
never fall back to a direct connection.

Retries retain only the public temporary-account intent. Every retry requires a
new recipient and protected prompt; a cancelled/failed prompt never falls back to
saved credentials. Shared pending attempts with different credential modes do
not coalesce. Local unsaved Quick Connect uses the separate owner admission below.

## Local unsaved Quick Connect

The local Quick Connect form retains public host, port, options and selected
credential/tunnel IDs. Username, domain and password fields are absent from this
form in protected mode. A temporary account is entered in the same isolated RDP
document used for saved connections, with a fresh recipient for every attempt.
Selecting temporary entry discards the saved primary reference for that attempt;
subsequent retries retain the temporary mode.

Main admits either a saved node ID or an exact public RDP target. The latter is
registered in the unlocked Go owner under a random ID, workspace, session and
main authorization epoch. The registry contains at most 64 targets, expires
authority after 15 minutes and is discarded on owner shutdown. It creates
no database node, row version or persisted metadata seal. Generic catalog/edit
operations cannot resolve these targets. Each scoped plan and bundle operation
revalidates the selected credential, independent gateway and tunnel metadata.
The existing native route and manual-only recipient contracts remain unchanged.

The controller owns the target lease until native shutdown is confirmed. It
releases the exact original target on terminal events, replacement, cancellation,
window reload/destruction and global shutdown. Global shutdown also joins late
registrations. Failed release requires a positive acknowledgement or confirmed
exit of the original Go owner; otherwise cleanup remains retryable and reserves
the session. A replacement workspace is never used to clean up an earlier target.
The stdio reader stops after the decoded terminal lock instead of initiating
another native read while the main loop closes the original owner.

Shared Quick Connect requires audited server admission and is still pending.
The shared owner rejects this local registry; a raw credential ID cannot grant
shared target access. Local [SSH/SFTP Quick Connect](vault-ssh-flow.md) uses
the same registry and its dedicated encrypted account/key/passphrase document. Local
VNC uses the same registry and its existing isolated password protocol; local
HTTP/HTTPS uses the [owned browser flow](vault-web-flow.md).

## Native process

`--operation rdp-sealed` is dispatched before legacy database initialization.
One process emits one ephemeral X25519 recipient and accepts one sealed opening
within 30 seconds. Opening metadata contains only the ciphertext, authenticated
binding, main-owned native owner handle, bounds and initial visibility intent. The private key is held in
secure memory and retired before the RDP adapter starts. The decrypted target,
identities and options cannot be replaced by Electron profile data.

Later messages accept only exact public surface/input/certificate/close controls
for that session, with canonical request IDs. Extra and nested unknown fields,
replayed openings, oversized input and cross-session commands fail closed.
App lock, stdin loss, output failure and process exit close the native session,
its sockets and forwarder and join the process workers. Output diagnostics are
generic. Native COM references never leave Go. The C# adapter still receives
metadata only; Go applies the primary and gateway passwords through its existing
local COM handoff. On Unix the existing private FreeRDP stdin path owns the
credential strings. Mutable buffers are wiped; immutable copies made by Go or
native client libraries cannot all be explicitly overwritten.

## Application integration

`vault-rdp.ts` validates bounded ciphertext and exact direct/routed binding
context. `VaultBackendClient` and `VaultBackendHost` expose typed main-only bundle
methods. `SealedRdpBackend` owns one child and route lease per session, waits for
a native start receipt, correlates bounded control receipts, and reserves IDs
until shutdown is confirmed. Recipient replay, stale owners/epochs/workspaces,
route loss, malformed output and failed writes retire the session. Failed
cleanup quarantines admission until an explicit retry confirms release.

`VaultRdpController` binds sessions to one WebContents owner, assigns a fresh main
lifecycle token for every attempt, drops stale callbacks and retires sessions on
reload/destruction. Certificates stay in a main-owned confirmation callback; a
missing or stale handler closes the session. Tooltip placement and screen-coordinate
geometry updates retain the existing native surface behavior.

`VaultRdpIpc` admits only a session ID, saved node ID, optional local credential
ID or temporary-account intent, and measured DIP bounds. Main derives the native window handle and screen
coordinates. At most 32 active, pending or idle surface reservations are retained.
Early disconnect cancels admission and waits for its original completion;
reload/destruction clears idle and pending reservations as well as native owners.
The authorization epoch is rechecked after admission commits. Lock and application
shutdown join the native owner and route broker, and cannot report success after
an unconfirmed stop. Current behavior disconnects protected RDP at every profile;
the Default/Standard hide-and-drop-reconnect-material policy remains open.

The normal preload exposes `openVaultRdpSession` with public identifiers and
bounds and temporary-account intent only. It exposes no recipient, bundle or plaintext credential API. Protected saved
local connections use this method, while the legacy `rdp:start` and system-client
paths refuse vault workspaces. Shared catalog nodes with protocol 1, including
inherited protocols resolved by Go, open owned RDP tabs. The existing `RdpSurface`
measures the mounted surface before admission, receives public status/frame
events and preserves inactive tabs. Reconnect requires a confirmed close receipt
and a fresh session ID in shared workspaces. Local saved RDP tabs use the canonical
node UUID as their stable surface ID; edits/deletion retain that ownership, and
each native attempt receives a fresh request ID and main lifecycle token.

Visibility is retained during planning, authorization and native startup. An
inactive or unmounted surface sends Hide even before the first Connected event.
The native C# adapter preserves that intent across Connected, LoginComplete and
AutoReconnected; these events cannot reveal a hidden background surface.

## Remaining RDP work

Shared unsaved Quick Connect still needs audited server admission. Local saved
and unsaved RDP connections support protected temporary entry; saved credential
editing and the owning Windows native RDP prompt remain available. Windows external/AzureAD execution and
successful real RD Gateway login have not been established by this work.
Profile-specific session retention, Direct-route prohibition at Hardened+ and
later security-profile enforcement remain part of the unfinished roadmap.

## Evidence and limitations

The complete backend suite passed in all 14 packages. Focused race tests include
real mstscax property setters and direct/SOCKS connections through the standalone
Go process. The official packaged Go executable passed that native test too;
the routed target deliberately cannot be reached directly. Tests also cover
native output loss, startup before database creation, malformed schemas, exact
options/inheritance, authentication graph failures and stale route rejection.
Windows arm64 and Linux amd64 cross-builds passed; Unix runtime RDP was not run.
No real remote account, successful server login or actual RD Gateway login was
available, so these are not interoperability claims for those scenarios.

All new production Go files exceed 80% statement coverage measured with the
project parser. The large legacy `rdp_profile.go` measures 85.71% of the modified
executable blocks (its unchanged legacy paths leave whole-file coverage 76.43%).
The new Electron modules exceed 80% line, branch and function coverage. Actual
main guards and geometry synchronization measure 100% V8 block coverage; main
initialization measures 97.44%, the shared RDP surface 85.71% and the existing local
RDP surface 100%. Modified C# executable lines measure 100% with Microsoft Code
Coverage. Logs, profiles and review notes are under `artifacts/vault/rdp-app-*` and
`artifacts/vault/rdp-sealed-*`.
Global vet still reports six existing unsafe.Pointer diagnostics in the Windows
clipboard package; vet of the modified package set passes. Global lint exits
successfully with 39 warnings outside this component. No warning was suppressed.
