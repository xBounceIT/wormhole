# Native VPN SSO archive transfer

Issue [#495](https://github.com/xBounceIT/wormhole/issues/495) now has a Go-owned
transfer state machine connected to [personal SSO archive custody](vault-vpn-sso-state.md).
The [owning browser session](vault-vpn-browser.md) now uses it for local SSL and
IPsec SAML. Source resolver/Use admission, a disposable recipient, actual supported
storage and signed local checkpoints are connected through native RPC. Shared
source equivalence remains pending. No ordinary renderer or preload can invoke
these archive operations.

## Context and cryptographic format

`vault.VPNSSOTransferContext` identifies personal custody workspace/file, native
profile/request/transfer/session/challenge, owner epoch and personal policy
sequence. A digest binds the full authenticated source/account/tunnel/route/TLS
context. The source checkpoint contributes revision, deletion status and digest.
Both ephemeral X25519 recipients are included. Revisions are decimal strings;
the epoch is bounded to JavaScript's exact integer range.

The archive remains opaque bytes, bounded to 64 MiB minus the 48-byte local record
header. Every chunk uses the existing HPKE X25519/HKDF-SHA256/AES-256-GCM suite
under the independent purpose `wormhole/v1/vpn-sso-transfer`. Its canonical info
contains these length-prefixed UTF-8 strings, in order:

1. Custody workspace, file, profile, request, transfer, session and challenge IDs.
2. Epoch, policy sequence, source revision and source-deleted flag (`1` or `0`).
3. Source digest, binding digest, capture public key and restore public key,
   each in canonical base64.
4. Direction (`capture` or `restore`), full archive byte length, full archive
   SHA-256 digest in base64, and zero-based chunk index.

Chunks are at most 4 MiB. Exact sizes and the complete digest are authenticated;
reordered, substituted, duplicated or partial inputs cannot be committed. A
missing or deleted source restores no archive and has zero chunks with the
SHA-256 digest of empty bytes. Capture always requires a nonempty versioned
archive, including when representing empty provider storage. Empty restore still
checks recipient identity and requires the exact native offer acknowledgement.
Public context or packet validation never grants source authority.

## Native owner lifecycle

`BeginVPNSSOTransfer` must be called only after fresh native source admission. Its
binding and minimum observation come from the resolver and protected device
anchor. The caller must also apply the effective source-workspace policy and
maintain that original authority while using the transfer; personal custody does
not authorize a shared connection. Those controller checks are not yet wired.

Begin imports the observation, allocates a protected native recipient, reserves
the exact custody source and seals restore chunks to the browser's recipient.
Returned metadata and ciphertext buffers are detached copies. At most four
transfers and 128 MiB of ciphertext may be retained. A five-minute timer retires
abandoned transfers. No archive plaintext is retained in a transfer stage.

`TakeVPNSSOTransfer` releases restore chunks in order and retires each retained
copy after delivery. The native recipient must verify the complete digest,
restore into an unpublished browser and anchor its observation before sending
`AcknowledgeVPNSSOTransfer`. Browser network activity/session publication must
wait for positive acknowledgement. Capture before acknowledgement is refused.
This receipt does not replace fresh gateway authentication or cookie issuance.

Every transfer action rechecks policy, expiry, immutable profile ownership and
the resident complete/partial source floor. A newer login, tombstone or imported
manifest observation refuses remaining restore chunks and acknowledgements as
well as further capture. It is insufficient to detect stale data only at save.

Capture chunks are retained as ciphertext. Commit authenticates every chunk and
the complete digest, closes the recipient key, and only then writes the archive
through the custody source/revision check. Plaintext is wiped on every outcome.
Successful commit consumes both transfer and profile. Failed commit retires the
attempt; retry requires a fresh transfer rather than reuse of a consumed key.
Loss of a commit reply therefore cannot replay the same capture.

Cancellation and profile/owner close join key retirement. A failed native key
cleanup remains reserved for matching retry and quarantines admission for the
owner lifetime. Old cleanup cannot remove a newer profile using the same ID.
Context substitutions refuse without cancelling the original transfer.

## Remaining browser and transport integration

The browser recipient must live in its owning disposable native secret context,
with pending crypto and storage application joined before cleanup. Archives must
represent actual supported provider storage, not only cookies. Serializer and
restore validation must exclude attempt-only VPN bearers and reject unsupported
storage rather than silently claim a complete archive. Current Fortinet flows
still use fresh volatile partitions and independent one-use gateway completion.

The [production native adapter](vault-vpn-sso-native.md) now enforces exact
schemas, bounded frames and local Fortinet SSL/IPsec SAML source admission. Its Electron
capability retains the original process and collects authenticated native device
observations on success or denial. It exposes no renderer IPC. The local browser
actors call it through their original-root session coordinator. Encrypted migration
inventories and shared source admission still need equivalent integration.

## Verification boundary

Go tests exercise production encryption, real SQLite custody, chunk order,
acknowledgement, stale source refusal, tampering, expiry, policy, key cleanup,
quarantine, buffer ownership, cancellation and ciphertext budgets. An independent
Node HPKE implementation exchanges two-chunk archives with the production Go
owner over synthetic test stdio and independently verifies the resulting local
record digest. Wrong purpose, ciphertext and original context are rejected.

The independent test fixture proves wire interoperability. Separate production
handler/client tests cover the registered native operations. Separate native
session tests establish real browser state round trips with Go custody for local
SSL/IPsec. Real provider interoperability and the entire roadmap remain unproven.
