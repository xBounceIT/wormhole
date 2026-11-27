# Fortinet IPsec in the vault

This is partial progress on [#495](vault-roadmap.md). Kind 9 is supported by
local metadata, signed shared tunnel records, route bindings and encrypted legacy
transfer. A protected editor can create and edit its gateway, IKE/ESP proposals,
address assignment and authentication configuration. Stored factors are never
hydrated into controls: PSK, password, client certificate, client private key and
CA certificate appear only as presence markers with explicit keep/replace/remove.
Switching authentication modes clears incompatible pending inputs and removes
incompatible stored factors on a successful write. Legacy profiles without an
explicit UserAuth retain their original SAML interpretation, not a weaker default.

The fallback chooser lists authenticated Fortinet SSL records from the same
workspace. Both edit and native full-save paths reject missing, deleted, foreign
provider and self references. Storing a reference does not authorize acquiring
or starting its route.

## Native PEM import

The protected document chooses a format; main owns the native file picker and
passes only an absolute selected path to Go. Go accepts bounded regular files
(up to 128 KiB) containing complete PEM certificate blocks or one unencrypted PKCS8,
PKCS1 RSA or EC private key. Wrong PEM types, invalid DER, encrypted headers,
multiple keys and unrelated/trailing content are refused. Certificate/private-key
matching occurs at save, after partial imports have been combined.

Importing a certificate, key or CA selects certificate authentication. Each import
merges the preceding authenticated stage for exactly the same editor and opening
record/provider into a new encrypted stage. A failed replacement leaves the
previous stage intact; changing provider cannot reuse it. The stage expires after
five minutes and is retired on save or editor shutdown. No temporary plaintext
profile or private-key file is created by the application. The preview uses a
one-use HPKE recipient and contains only public settings and field presence.

## Runtime boundary

The common sealed route recipient can launch the native IPsec sidecar for PSK or
certificate authentication with disabled or saved user authentication (UserAuth
0 or 2). It validates the complete configuration and binds its HPKE envelope to
workspace, file, node, session, request, endpoint, epoch, provider and exact record
and configuration versions. Configuration and factors travel through stdin;
provider diagnostics are discarded. Cancellation and app lock retire the owned
route. This path does not call the legacy launcher, prompt broker or caches.

Prompt-on-login (UserAuth 1) now creates a fresh, locked X25519 recipient in the
native route process. A dedicated protected document asks for the password and,
only when the configuration has no username, a temporary username. The document
clears its controls before encryption; preload and main receive only an HPKE
envelope. Its separate authentication purpose binds every route identity and
revision, a one-use challenge and the expected username shape. Native Go rejects
replay, wrong contexts, malformed UTF-8, control characters and fields over 4096
bytes. A stored username cannot be overridden, and a stale saved password is
never reused. Only the transient launch uses the supplied factor; the saved
configuration is unchanged.

SSH/SFTP, web, RDP and VNC route brokers parent the dialog to the original session
owner. Prompts serialize across protocols, while cancellation removes a queued
attempt without waiting for another dialog. EOF, lock, navigation, timeout or
origin retirement cancels the matching prompt and native attempt. Cleanup must
confirm both window and process destruction before the route reservation can be
reused. Once ready, pooled consumers retain their usual independent leases.

SAML (UserAuth 3, including legacy profiles with omitted UserAuth) now uses a
separate one-use native recipient and purpose-bound browser reply. Go owns the
random UID, reserved callback port, HTTPS negotiation and selected gateway.
The native browser has no preload or application IPC and uses a fresh volatile
profile for every attempt. It intercepts the exact main-frame loopback callback
before HTTP, encrypts the token and clears the profile after confirmed window
destruction. The hexadecimal token keeps its original spelling because it is an
opaque EAP password. A native-only launch witness binds the resulting configuration
to this route; saved token-shaped fields cannot bypass browser authentication.

Gateway certificate exceptions are confined to the original HTTPS origin. Other
ports or hostname aliases cannot inherit that exception; other IdP hosts retain
normal certificate validation. Navigation, crashes, lock and owner retirement
cancel the attempt. Failed destruction or storage cleanup blocks new browser
admission until the original cleanup succeeds. One owner watcher covers concurrent
attempts, and main creates each partition independently of native challenge IDs.
HTTP redirects may abort the initial page load; actual load-failure events own
cancellation so a valid callback cannot be cancelled by an old load promise.

The native browser now restores supported provider state from an encrypted
personal archive before navigation and captures it before returning a fresh SAML
result. Shared sources use personal/device custody and current Source Use checks,
with migration 42 supplying final enrolled author/recipient proofs. Unsupported
worker/cache/nonextractable-key storage and the remaining security profiles stay
unavailable. [Configured SSL fallback](vault-tunnel-fallback.md) now uses an
explicit native primary actor, confirmed original-process retirement and
independent target authorization per consumer across all four route brokers.
Hardware/profile requirements and real provider interoperability remain open.

[Native process retirement](vault-tunnel-retirement.md) now retains the original
VPN controller until its sidecar's OS exit is confirmed. Main cannot force-kill
the controller on a short timeout or replace an unconfirmed route by changing
its configuration version. The fallback broker joins this barrier before
requesting a fresh secondary plan or creating its separate recipient.

## PostgreSQL and verification

Schema 41 extends the schema-40 kind constraint with identity/version guards and
no grant changes. Runtime user/admin/enrollment roles remain unable to access
private tables and helpers. The existing shared signature, independent boundary
permissions and audited ciphertext-release rules apply unchanged to kind 9.

Tests cover redaction, method transitions, typed settings, fallback validation,
unknown-kind rejection, complete legacy transfer, bounded PEM import, atomic
multi-file assembly, invalid replacement and stage retirement. Chromium tests
exercise secret clearing and conditional controls. Real Electron-client/Go tests
verify kind-9 catalog metadata and HPKE editor projections without returning the
PSK. The native recipient is exercised with real pipes and a synthetic sidecar;
live PostgreSQL localhost tests apply migration 41 and run the release graph and
permission checks. These establish the software boundaries, not successful login
to a real FortiGate gateway. Native execution is verified on Windows x64; ARM64
compilation and other-platform runtime coverage are reported separately.

Prompted-factor tests additionally verify Node/Chromium-to-Go interoperability
for UTF-8 and fixed usernames, purpose substitution, byte clearing, late results,
queued cancellation, shared-route origin retirement and failed-close quarantine.
The Go route tests verify a fresh factor replaces a stale one only for the native
launch, and app lock closes the resulting route.

SAML tests run real isolated Chromium against local synthetic HTTPS gateways and
the production Go recipient. They cover JavaScript and HTTP redirects, mixed-case
tokens, malformed callbacks, cancellation and absence of HTTP to the reserved
callback port. Packaging tests stage the actual runtime manifest into a separate
directory and load the native sender without repository dependencies. These are
software-boundary tests and do not establish a real FortiGate login.
