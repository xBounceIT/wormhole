# Shared account key retrieval

Migration `0006_account_keys.sql` upgrades schema 5 to 6 and exposes
`wormhole_api_v1.account_keys(capability)`. The capability must belong to an active
device with current credential proof and audited session admission. The API takes
no user identifier and reads only the authenticated user's encrypted private-key
capsule. There is no administrator override or direct table grant.

The API returns workspace/user identity, encryption/signing key references,
wrapping revision, KDF preset, ASK requirement, nonce, ciphertext and current
authentication epoch. Missing wrappers, wrong key ownership and inactive key
references fail closed. Admission holds shared user/device/account locks and the
wrapper read adds a shared NOWAIT lock, preserving consistency with the password
change transaction. Future account-key rotation/enrollment writers must acquire
the same user lock before modifying account key metadata.

The Go `Session.AccountKeys` method uses the retained native session capability
and the existing bounded query transport. It validates the exact response shape,
canonical UUIDs and positive bounded integers, authenticated workspace/user/epoch,
distinct key references, known KDF presets, exact boolean representation and fixed
v1 capsule sizes. Malformed responses invalidate the connection owner. Callers
must still call `Close` to confirm cleanup after invalidation.

The returned `UnverifiedAccountKeys` is deliberately not a verified key graph or
policy. The caller must independently authenticate key references and public keys,
check wrapping rollback state, and compare KDF/ASK requirements against signed
policy before using [certified key opening](vault-shared-user-certificates.md).
It must never let server metadata weaken
password derivation or omit an ASK. The native retrieval method releases no private
keys, does not derive passwords and is not exposed through renderer IPC.

Tests cover parser bounds and malformed fields, buffer independence, unavailable
sessions, migration identity/version guards, invalid capability, missing own
wrapper with another user's row present, foreign key ownership, retired encryption
and signing keys, private-table denial, absence of PUBLIC function execution and
retrieval before/after an actual PostgreSQL password change. Go statement coverage
is measured. SQL coverage uses these behavioral integration checks because the
project has no PL/pgSQL coverage instrumentation.

Migration `0007_account_certificates.sql` upgrades schema 6 to 7 and adds
`account_key_material(capability)`. It reads the capsule and both user-key
certificates in one server transaction, retaining shared NOWAIT locks on the user,
wrapper and key rows. Certificate metadata must be complete, both keys must belong
to the current user and be active with the expected suite, and both certificates
must identify the same organisation signer. Missing certificates fail closed.
The new function has no PUBLIC execution grant and exposes no direct table access.

The separate `keys.cert_revision` field records the revision covered by the
organisation signature. It is not inferred from mutable `row_version`; normal
metadata updates cannot silently rewrite a certificate's signed revision. Migration
leaves existing keys uncertified instead of fabricating revision/signature values.
Enrollment and reset must explicitly provision complete certificates.

`Session.AccountKeyMaterial` uses this endpoint without falling back to the older
capsule-only endpoint. Its exact 24-column parser reuses capsule validation and
checks both public keys, signatures, signer UUID/version and certificate revision
encodings. The returned `UnverifiedAccountKeys` includes both certificate objects;
`AccountKeys` remains the explicit capsule-only API and leaves them nil. Neither
method verifies signatures against a database-supplied organisation key. The caller
must supply its independent organisation pin to `vault.OpenCertifiedUserKeys`.

Real PostgreSQL tests retrieve and verify both certificates, open the capsule before
and after password replacement, reject missing certificate revisions, refuse a
contended certificate row and confirm that mutable row revisions are independent.
A deliberately forged database signature is returned as unverified data and rejected
by certified opening before any private keys are released. Parser tests cover
malformed shapes, suites, key/signature sizes, hex, signer identities and numeric limits.

Migration `0008_account_state.sql` adds private `user_key_states` storage with a
positive sequence and a bounded canonical signed document supplied by native
issuance. The database enforces size/counter bounds; the client independently
checks canonical encoding, embedded identity, sequence consistency and signature.
No state is invented for existing accounts, and runtime users/admins receive no
direct table access.

`account_key_state(capability)` reads only the authenticated user's state, under
a shared NOWAIT lock. It does not require a usable old capsule or certificates,
so an already authenticated caller can retrieve a signed revocation even when
those records are incomplete. Normal device/account admission checks still apply;
this is not an unauthenticated or disabled-account endpoint.

`account_unlock_material(capability)` reads state, capsule and both certificates
under one transaction and the existing shared user/account/key locks. The native
`Session.AccountUnlockMaterial` decodes exactly 26 columns and rejects inconsistent
identity, key selection, signer or embedded/database sequence. It never falls back
to older endpoints. `Session.AccountKeyState` provides the separate state-only read.
Both return unverified signed data: callers must verify it against their independent
pin, advance and persist trust floors, and use `vault.OpenCurrentUserKeys` before
publishing private material. Current admin mutation writers must acquire the user
lock first and update signed state and associated key graph atomically.

Real PostgreSQL tests exercise complete retrieval/opening before and after password
change, signed revocation with unavailable certificates, old active-state replay
rejection, later signed reactivation, missing-state failure, state-row contention,
private-table/ACL restrictions and bounded storage constraints. Native codec/parser
tests cover canonical JSON and malformed, mixed-account or inconsistent responses.

Production account provisioning, admin state mutation APIs, trusted unlock
orchestration, local trust-root password transition/reconciliation and UI wiring
remain separate work. This API does not by itself make a shared workspace usable.
