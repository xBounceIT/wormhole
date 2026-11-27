# Signed current user-key state

`vault.UserKeyState` is an organisation-signed selection of the current encryption
and signing key references for one user. It binds workspace/user identity, a positive
sequence, active/revoked status, both key references, minimum certificate revisions
and the organisation signer reference. These sequences are independent of password
wrapping revisions, certificate revisions and database row versions.

Version 1 signs fixed-order JSON with a null signature field under the canonical
domain `wormhole/v1/user-key-state`. Workspace/user/key IDs must be nonzero; both
user keys and the organisation signer must be distinct. Key versions fit positive
PostgreSQL integers, and sequences/certificate floors fit positive bigints.

`UserKeyTrust` supplies independent identity, organisation pin, minimum previously
accepted state sequence and minimum wrapping revision. `VerifyUserKeyState` checks
the signature and identity before applying the sequence floor. A signed revocation
verifies successfully: the caller must persist it before denying access, so an old
active state cannot undo an observed revocation.

`OpenCurrentUserKeys` first authenticates the state, rejects revoked accounts and
requires the wrapper's key references to match the signed selection. It applies
the trusted wrapping-revision floor and then verifies both certificates with their
signed minimum revisions before opening the AEAD capsule. No private pair is
returned for revoked, superseded, malformed or mismatched material. The caller owns
and must wipe a successful private result.

These primitives do not provide a freshness oracle: a client cannot detect a newer
revocation it has never observed when every source withholds it. Durable sequence
floors prevent replay below observed state; same-sequence equivocation requires a
persisted authenticated state digest or complete record as well. The
[format-3 trust file](vault-shared-trust-state.md) now retains the complete signed
record and enforces monotonic transitions. Schema 8 adds
[SQL state storage and retrieval](vault-shared-account-keys.md). Admin mutation
transactions and application unlock orchestration are still pending. No caller may
infer this state from unsigned database flags.

`EncodeUserKeyState` and `DecodeUserKeyState` enforce a canonical, bounded 4096-byte
document with a 64-byte signature. Unknown/duplicate fields, case aliases, whitespace
variants, invalid bounds and unsupported formats are rejected. These codecs check
structure only: decoding a correctly sized forged signature does not authenticate
it. `VerifyUserKeyState` with independent trust remains mandatory.

Tests verify active opening, authentic revocation, rejection of old active state
after raising the sequence floor, wrapping rollback, new key selection, raised
certificate floors, wrong master, every signed-field mutation, wrong/missing pins,
unsupported versions and integer/key-reference bounds.
