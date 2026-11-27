# Native VPN browser recipient and origin storage

Issue [#495](https://github.com/xBounceIT/wormhole/issues/495) remains incomplete.
The local Fortinet SSL and IPsec SAML authentication actors connect the disposable recipient,
Chromium storage driver and native vault custody at Default/Standard. It restores
before allowing network/presentation, and commits encrypted storage before returning
the separately bound fresh VPN completion. Shared retention and the wider
roadmap remain incomplete. Real provider interoperability still needs manual tests.

## Owning session and application integration

`VaultVPNBrowserSession` captures the original window, route request (including
credential override), executable, root authority and authorization callback before
awaiting initialization. The host reservation cannot select a replacement root.
The effective authenticated profile must be Default/Standard; Standard requires a
locked recipient key. The root transfer policy sequence must match that profile.

Restore performs native root begin, recipient decryption, actual Chromium import,
root acknowledgement and only then network/presentation. Capture reads the original
volatile browser, seals through the disposable Go recipient and commits through the
original root. The final `SVPNCOOKIE` is excluded, and the existing independent
gateway-response/HttpOnly-cookie-store proof remains mandatory for its fresh handoff.
IPsec intercepts the original loopback callback before HTTP and commits retained
state before returning its separate purpose-bound fresh token envelope. URL history,
page markup and native completion frames are not part of the storage archive.
All four protected Connect route callbacks forward the original request.

Each asynchronous admission reserves its cleanup handle before a final gate can
fail. Closing destroys the exact window, aborts native work, joins startup/capture
and closes both existing and late root/helper/driver handles. Failed cleanup retains
the actor for an exact retry. Invalidated native inventory blocks network immediately
and cancels its owning actor. There is no preload or ordinary renderer endpoint.
If root cancellation cannot be acknowledged, the native host must confirm exit of
that original process. It retires an active original owner before waiting, or joins
the captured old client when a replacement exists. It never retires the replacement;
unconfirmed process exit keeps cleanup pending.

`VaultVPNStorageDriver` requires an in-memory partition. Its private synthetic HTTPS
documents have a restrictive CSP and an exact request allow-list. It records native
storage keys plus the complete supported ancestor-origin chain, recreates nested
iframe contexts and verifies each actual key before importing or reading state.
Cross-process targets retain their native parent relationships; detaching a parent
also removes descendant target sessions. Alias keys restore shared local/IDB state
once while retaining the original window's session-storage namespace.

Cookies retain host-only/domain distinctions, path, security, expiry, priority,
source attributes and CHIPS partition keys. Opaque keys, unknown attributes and
duplicate identities are refused. A native read-back verifies actual restoration
before acknowledgement. Expired persistent cookies remain deleted; ordinary
expiry at rest or during import does not bar a fresh sign-in. Source usage is checked before reading IDB values, and
encoded sizes are accumulated across contexts/cookies before building the archive.
The destination is disposable: any partial import fails closed and is destroyed.

Worker writers, service workers, Cache Storage, unsupported quota state and
non-extractable keys currently cause refusal rather than a partial snapshot. These
need further native adapters. Imported legacy raw profile inventories also need
their consuming adapter. Shared sources still use their volatile fresh-login flow;
their equivalent personal/device-root custody is pending.

For IPsec, Go requires the authenticated SAML mode and validates the actual selected
gateway against the primary host or configured remote gateways, using the configured
SAML port (legacy default1001) and TLS policy. Each selected gateway has its own
retained scope. Fresh SAML query parameters stay bound to the completion context
without selecting a different retained archive. Source/policy rechecks remain
mandatory on every transfer action; configuration changes cannot release old data.

## Disposable recipient

The backend operation `vault-vpn-browser` starts before legacy database or logging
initialization. It owns one ephemeral X25519 private key in `securemem`, disables
process dumps, exposes only its public recipient/profile metadata and has no
database, network listener or archive file. Key memory lock status is public
metadata for the eventual policy gate. Hardened/Paranoid remain unavailable.

The private native channel uses a big-endian 4-byte JSON-header length followed
by that exact header and any declared binary body. Headers are limited to 8 MiB;
raw storage bodies to 4 MiB. Archive bodies travel as binary data over the pipe
and never enter command-line arguments or protocol diagnostics. This channel is separate from the normal
vault transport and belongs only to the native Chromium storage controller.

Bind pins the helper-generated profile/recipient and the original root transfer
context/manifest. Ordered root restore chunks are authenticated with the existing
purpose-bound VPN SSO codec. The complete archive digest must authenticate, and
the recipient key must close successfully, before any plaintext chunk is emitted.
Every emitted chunk is wiped. A missing/deleted source restores zero bytes.

Capture accepts a nonempty archive of at most 64 MiB minus the custody header,
with exact ordered binary chunks. It seals to the original root capture recipient
and emits ciphertext packets plus a complete digest. Plaintext is wiped on every
outcome. EOF, explicit close, protocol failure and a five-minute deadline retire
the helper. Native process exit, including an independent Windows wait proof
when necessary, determines whether cleanup succeeded.

`VaultVPNBrowserRecipient` bounds framing and queued output, validates and pins
contexts/manifests, checks the plaintext restore digest and joins writes/work
with process retirement. It consumes capture input, including on refused/busy
calls. Unexpected bodies in control phases are wiped. Lost authority after a
reply wipes an unreturned restore buffer. A failed native exit stays reserved;
new recipient admission retries that exact cleanup and remains barred while it
is unconfirmed. It captures the original executable, signal and authority function
before waiting and rechecks that authority afterward. There is no preload or
ordinary renderer endpoint.

## Origin document serializer

`vpnStorageDocument` runs as self-contained compiled code in an isolated,
native-owned offline HTTPS document. It verifies the exact origin and absence
of Node/the app bridge. It reads/writes local and session storage and IndexedDB
database versions, object-store key paths, index definitions and record keys.

Its structured-value graph preserves cycles, shared references, sparse arrays
and their properties, maps, sets, dates, regular expressions, binary buffers and
views, BigInt, special numeric values, Blob/File and extractable WebCrypto keys.
Object properties are defined without invoking prototype setters. Unknown types
and malformed graphs are refused. Bounds apply symmetrically before capture and
restore, including names, counts, graph nodes and encoded size.

Auto-increment state is read using an aborted probe transaction. Restoration
advances the generator without retaining a probe row or overwriting an existing
record. Deleted high keys, the final valid generated value `2^53` and exhaustion
are preserved. Index definitions are read while the source transaction is live.

The serializer requires a fresh destination and refuses an existing database.
It does not promise transactional import across all databases; its caller must
destroy an unsuccessful volatile profile and must never enable network or
presentation until root acknowledgement follows successful application.

Service workers, Cache Storage and non-extractable WebCrypto keys require further
native adapters; their presence is explicitly refused instead of silently
publishing a partial copy. The complete session driver must also inventory
partitioned storage, cookies and other storage types and enforce the same rule.
This origin codec alone is not a complete provider-profile snapshot.

## Evidence and remaining connection

Real subprocess tests exchange two-chunk archives between the Go CLI recipient,
the production Electron client and real encrypted SQLite custody. Tests cover
wrong recipient/context, ciphertext, size/order, partial frames, cancellation,
cleanup quarantine, detached inputs and diagnostic redaction. Real Chromium
tests round-trip the supported DOM/IndexedDB state between independent memory
partitions and verify structured types, schemas and key generators. They also
exercise malformed state and explicit refusals.

Additional native proofs verify that `Network.getAllCookies`/`setCookies` stay in
the inspected session, including separate cookie partition keys. They also obtain
actual iframe storage keys and evaluate isolated worlds through related CDP
sessions when Chromium puts cross-origin frames in another process. The effective
storage key controls isolation across top-level contexts and survives returning
to the original context. The actual session driver and actor now use these APIs.
End-to-end tests exercise the real Go vault, disposable recipients and two separate
Chromium sessions for local AND shared SSL and IPsec, with different request/session/epoch
and fresh route planning. IPsec SAML queries also differ between attempts.

Encrypted migration inventory consumption, unsupported provider storage adapters,
complete live shared deployment validation and the rest of the #495 roadmap remain
required. Shared browser retention now uses the device's personal owner and fresh
audited source admission; enrolled sources require deployment migration42. These
tests do not establish interoperability with a real identity provider or VPN gateway.
