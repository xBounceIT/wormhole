# Password-wrapped shared user keys

Native `SealUserKeys`, `OpenUserKeys` and `RewrapUserKeys` protect the final user
encryption private key and signing seed. These are cryptographic primitives;
they do not enable daily login or implement the password-change database API.

Their input is the 32-byte account master after Argon2id and the policy-required
ASK mix. Callers must verify the signed security policy and use the existing
`SharedSalt`, `DerivePassword` and `MixAccountSecret` flow. The primitives neither
accept a raw password nor decide whether ASK is required. Password change must
retain the existing ASK; an administrative reset issues a new one.

`UserKeyBinding` supplies independently authenticated workspace/user IDs,
distinct encryption/signing key references and a positive wrapping revision.
Key versions fit PostgreSQL positive integers and wrapping revisions fit positive
bigints. These coordinates are length-prefixed under
`wormhole/v1/user-key-context`, with raw UUID bytes and big-endian numeric values.
SHA-256 of that context salts the existing `wormhole/v1/unlock` HKDF derivation.

The existing AES-256-GCM envelope uses workspace, table `Users`, user as owner,
`private-keys/` plus the hex context digest as field, and the encryption key
ID/version. Plaintext is exactly 65 bytes: format byte 1, 32-byte X25519 private
input, and 32-byte Ed25519 seed. Ciphertext must be exactly 81 bytes. Temporary
unlock keys and plaintext are wiped on every exit.

Opening also derives both public keys and compares them with the caller's
independently certified pair. Incorrect credentials, altered context, unsupported
inner format, malformed public keys or mismatched private material return no
keys. Successful output is temporary native `UserKeys`, excluded from JSON and
requiring owner-managed wiping or transfer into protected memory.

Rewrapping authenticates the old container, increments only the wrapping revision
and encrypts the same private pair under the new account master. It rejects
revision overflow and returns no partial replacement on failure. The input
masters, original envelope and caller-owned key material are borrowed and remain
unchanged. Login-derived material cannot open the container.

The [SQL `change_password` transaction](vault-shared-password-change.md) now compares
the current revision, publishes the new wrapper and updates device SCRAM verifiers
atomically, advancing the account epoch and invalidating old admissions. Native
request/UI orchestration remains incomplete. The rewrapping primitive alone does
not revoke live sessions, establish certificate trust,
authenticate a revision supplied by a hostile database, or detect restoration of
both an old wrapper and its external revision floor.

Tests cover round trips, unchanged private keys across a password change,
rejection of old masters on new containers, every context coordinate, public-key
mismatch, purpose separation, tampering, malformed/oversized identifiers and
versions, invalid inner format and maximum-revision failure without partial output.
