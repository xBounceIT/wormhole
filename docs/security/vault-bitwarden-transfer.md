# Bitwarden sealed transfer format

This implements the native/browser cryptographic format and isolated-context
sender/recipient for issue #495. Real Go, Node and sandboxed Chromium tests verify
the exchange. Production native staging/RPC and its main-process SDK now use
this format. Extension installation/settings and browser lifecycle integration
are still open. Vault web browsers continue to skip the legacy Bitwarden extension
flow. This format is public context binding, not an application authorization.

## Context and authentication

Each context contains canonical nonzero UUIDs for workspace, file, profile,
request and transfer; a positive JavaScript-safe authorization epoch; a positive
canonical int64 policy sequence; action `hydrate` or `capture`; a canonical
nonnegative int64 source revision; and separate 32-byte capture/restore public
keys. The native controller generates the transfer identity, checks the current owner
and policy, and fences its lifetime. Revisions use decimal
strings so JavaScript retains every bit.

Every chunk uses the existing X25519/HKDF-SHA256/AES-256-GCM HPKE suite and its
fixed suite/format identifiers. Its info is the UTF-8 domain
`wormhole/v1/bitwarden-browser-transfer`, followed by uint32 big-endian lengths
and UTF-8 values in this exact order:

1. workspace ID, file ID, profile ID, request ID, transfer ID;
2. decimal epoch, policy sequence, action, source revision;
3. canonical base64 capture public key, canonical base64 restore public key;
4. direction, total frame bytes, revision, restore flag (`0`/`1`), chunk index.

Direction `capture` goes to the native recipient and must use the source revision
with restore=false. Direction `restore` goes to the isolated recipient and cannot
regress the revision. Go checks that the private key matches the public key bound
to that direction. Context, revision, size, index and direction retagging fail
HPKE authentication even when the altered metadata remains formally valid.
This purpose cannot be used as a protocol, credential-display or recovery bundle.

## Frame and packets

A frame is version byte 1, reserved byte 0, uint32 big-endian local/session byte
lengths, then the exact two UTF-8 JSON object byte sequences. Each area is 2 bytes
to 8 MiB. Numeric JSON values are validated without rewriting their bytes.
The native storage owner separately validates its stricter state schema/merge
rules. Go's borrowed decoded payload rejects ordinary JSON marshaling.

A packet has exactly `context`, `direction`, `manifest`, `index` and `bundle`.
The manifest has exactly total `bytes`, decimal-string `revision` and boolean
`restore`. The bundle has exactly `formatVersion`, `suiteId`, `enc`, `ciphertext`.
Base64 encodings, metadata fields, lengths and envelope sizes are strict.

Frames split into 4 MiB chunks. A maximum frame (16 MiB + 10 bytes) uses five
packets. The actual final-chunk size, total size, count and index are checked;
each serialized packet fits the existing 8 MiB stdio bound. The Go assembler pins the complete context and first manifest, enforces ordered
one-time reception, and rejects incomplete or replayed transfers. The isolated
recipient already implements those sequential/one-transfer semantics.

## Isolated data lifetime

The capture sender consumes both caller buffers before asynchronous encryption.
It retains one bounded frame and emits one ciphertext packet per `next()` call,
never an array of all packets or plaintext. Completion, disposal, cancellation,
crypto failure and concurrent calls retire it and clear its frame.

The restore recipient generates a nonextractable X25519 key, binds once, and
retires after its first complete transfer or any invalid attempt. Plaintext is
borrowed only by an extension-local callback. `accept()` returns a public
revision/restore receipt. The callback receives an AbortSignal and must fence
its asynchronous storage operations. Disposal immediately clears partial chunks
and the active assembled frame, including while the callback is still pending.
Byte clearing is best effort; dropping CryptoKey references is not a claim of
physical key zeroization or complete application lock/relock behavior.

## Verification boundary

Go tests authenticate every context/manifest field and valid-size index/length
substitutions, wrong direction with equal recipient keys, malformed framing,
invalid JSON, int64 boundaries and maximum frames. JavaScript tests cover strict
contracts, one-use binding, ordering, interleaved manifests, crypto failure,
concurrent calls, cancellation, failed apply, immediate borrowed-buffer clearing
and maximum transfers.

A real compiled Go fixture receives ciphertext captures and sends ciphertext
restores for small and maximum inputs. A sandboxed, context-isolated Chromium
window with no Node/app bridge runs the same sender/recipient code; its main
process exchanges public context, ciphertext and receipt only. Unicode and
full-width decimal revisions are exercised. These fixtures do not open user
profiles and do not establish real Bitwarden login, relock, installed-extension
compatibility. A separate production-service test exercises the real stdio
handler, native Electron client and encrypted SQLite, maximum five-chunk transfers,
profile closure, cancellation, replay rejection and restart. Local state survives
restart encrypted; session state does not.

## Production native staging

The native owner allows four pending transfers, one per profile, at most 64 MiB
of retained ciphertext and a two-minute deadline. Capture private keys live in
securemem and are released before the storage engine may commit. Capture chunks
remain sealed until commit; plaintext exists only during native decrypt/merge/seal
and is wiped on return. A failed release is reported, keeps an unconfirmed key
reservation when needed, and prevents further transfers for that owner lifetime.
Timers, explicit cancel, profile close and owner close all retire staged material.

The stdin operations are `bitwarden-transfer-begin`, `-push`, `-commit`, `-take`,
`-cancel` and `bitwarden-profile-close`. Every nested object has exact, unique
field names; base64 must be canonical. Begin receives an epoch as a decimal string;
public contexts use safe integer epochs. Commit returns only a manifest. Take
moves one sealed packet once; its native caller marshals before clearing it.

The main-process capability captures the exact backend instance, workspace and
browser authorization callback. It rechecks authority before and after each await;
late results cancel on the original backend. Cancel and profile cleanup remain
bound to that captured backend, including after replacement. Cleanup failures are
reported and can be retried. No general preload/renderer IPC registers these APIs.

The extension must capture its actual state after applying a restore. An outgoing
snapshot does not advance the native merge base to an assumed successfully restored
state. Failing to acknowledge a restore before later edits can legitimately keep
concurrent account fields, including rejecting a merged result that exceeds limits.

## Isolated storage adapter

`src/vault-bitwarden-extension-storage.ts` runs only in the owning extension
background world. MV2 reads `bitwardenMain.memoryStorageForStateProviders` through
its store/save/remove interface; it refuses a missing background service even if
chrome.storage.session is present. MV3 uses its actual chrome.storage.session.
The adapter is not imported by React, preload or main-process storage flows.

Each capture owns two bounded byte arrays, at most 8 MiB and 65536 keys per area.
The caller passes them directly to the sealed capture helper and owns their
clearing. Partial capture failures, including a late abort after the last read,
clear both buffers. Restore borrows desired and actual-witness arrays, validates
them, and applies session state before local state. It issues only changed keys,
without clearing the area, and preserves additions/deletions/updates that differ
from its captured witness. Private runtime errors never escape.

Conditional comparisons and edits run together inside the native get callback or
memory-service turn; there is no local awaited snapshot-to-write gap. Chrome does
not provide transactional CAS against noncooperating contexts, and an already
issued native write cannot be recalled. Abort and a 10-second operation deadline
prevent later writes and acknowledgements. Owning document destruction/session
cleanup remain required for application lock. The installed-extension runtime
and app lifecycle wiring are still pending; these helpers alone do not activate
the native vault Bitwarden toolbar or prove real third-party login/relock.

## Isolated controller and distributed asset

The extension controller owns one stage with a 120-second deadline. Its public
interface exposes only prepare request metadata, bind manifest, next ciphertext,
accept receipt, cancel and dispose. It binds one workspace/profile/authorization
epoch and keeps source revisions privately as decimal strings. First use hydrates;
a completed exchange enables capture. Any failed/uncertain exchange retries through
hydrate, preserving the last received revision. Late work from a canceled stage
cannot retire or change a newer stage. Permanent document disposal prevents reuse.

Actual capture bytes are consumed by the sealed sender; a separately owned bounded
witness stays in the extension for conditional restore. Every completed copy is
registered before another secret allocation. Final receipt, cancellation, timeout
and failure retire witness, capture frame and recipient. Only a complete successful
receipt advances revision. A later actual capture must acknowledge the resulting
storage; an outgoing requested restore remains insufficient proof of application.

The existing build:electron pipeline emits vault-bitwarden-extension.js into the
normal distributed files. It is one browser IIFE, has no external imports, source
map or app bridge, and resolves HPKE's optional crypto import to browser WebCrypto.
The factory requires a secure chrome-extension origin whose host matches its actual
runtime ID, a supported manifest and the real background storage service. It never
accepts storage values from main. The main-owned document endpoint is implemented below. Safe extension hosting and
application lifecycle wiring remain required before native vault browsers expose Bitwarden.


## Native synchronization coordinator

`VaultBitwardenSynchronizer` binds an exact extension bridge, workspace/profile/epoch
and original Go client. The host creates it only for its currently unlocked workspace;
subsequent exchanges recheck that same client and authorization. No preload or general
renderer IPC exposes this factory. File identity and policy sequence stay pinned.

The coordinator validates every capture/restore manifest, packet order and final receipt.
A restore triggers a new capture of actual extension storage. At most three exchanges
run per checkpoint; a concurrent refresh that still requires restoration returns a
public `checkpointPending` flag for later scheduling. Concurrent callers share one
checkpoint. Source revisions and plaintext storage remain in the extension/native owner.

Failure cancels both sides on their original owners. Unconfirmed cancellation, including
failure while a late native begin is being retired, quarantines the coordinator. Close
stops admission, disposes the extension bridge, waits for late original-owner operations
and closes the native profile. It requires exact positive cleanup acknowledgements,
reports failures without private diagnostics, and permits an explicit cleanup retry.

This coordinator does not install the extension or create a browser document. Application
integration must use the exact-document endpoint below, reserve
profile lifetimes, schedule bounded checkpoints and await document destruction/storage
cleanup on lock. A coordinator or bridge-dispose receipt alone is not proof that all
extension/background/popup contexts have been destroyed.


## Exact background-document endpoint

`VaultBitwardenDocumentEndpoint` binds the native session, loaded background page,
main-frame object and native frame/process identifiers to one owner and exact URL.
A trusted native sandbox-provenance callback must positively admit that frame.
The packaged asset installs a document token; navigation, destruction and crashes
revoke the endpoint even when the URL is reused. No generic renderer IPC exposes it.

Both sides validate bounded metadata and ciphertext before serialization. Calls have
monotonic identifiers, deadlines and cancellation generations. Queued stale calls
cannot publish results or reactivate a canceled exchange. Disposal retains a tombstone
in the original document, preventing owner substitution while native storage writes
may still be outstanding. A pending bootstrap cannot acknowledge cleanup merely
because its public timeout expired. Disposal is not proof of browser-wide destruction.

Native tests exercise the packaged asset in an actual sandboxed Windows extension
background, real Go staging, restoration between profiles and encrypted persistence
across a Go restart. Their persistent Chromium profiles are diagnostic fixtures only;
this does not establish real Bitwarden login, application relock or release support
on every platform.

### Unresolved hosting requirement

Electron 44.10.1 refuses extensions in nonpersistent sessions. Its
[extension API](https://www.electronjs.org/docs/latest/api/extensions-api)
requires a persistent session. A native diagnostic also confirmed that synthetic
`chrome.storage.local` data reaches disk in such a profile. Consequently, persistent
profiles are not an acceptable fallback for the vault's memory-only hosting requirement,
and this endpoint does not enable the native vault Bitwarden button.

Remaining integration requires a protected extension runtime/storage design,
Go-owned authenticated installation and settings, trusted sandbox provenance on every
supported platform, profile admission and route ownership, popup/checkpoint scheduling,
and positive document destruction plus storage cleanup on lock. The Windows native
fixture uses OS sandbox metrics; an unknown sandbox capability is rejected. Neither
an endpoint disposal receipt nor a successful native-service restart proves all of
these application lifecycle requirements.
