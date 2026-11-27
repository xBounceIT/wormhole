# Signed HPKE key copies

The native `internal/vault` key-copy operations implement cryptographic wrapping
and rewrapping for the shared key graph. They do not implement SQL permissions,
certificate-chain resolution, transactional enrollment or a usable shared tree.

`KeyCopyBinding` contains an expected workspace UUID and three independently
resolved key references: copied key, holder encryption key, and issuer signing
key. Every reference has a nonzero UUID and a version from 1 to 2147483647,
matching PostgreSQL `integer`. The copied key and holder reference must differ,
as required by the `KeyCopies` table constraint. The caller must authenticate the
references and the issuer public key; the copy cannot select its trusted signer.

`SealKeyCopy` wraps exactly 32 bytes (a symmetric key or private seed) using the
existing RFC 9180 X25519/HKDF-SHA256/AES-256-GCM implementation. Its HPKE info is
the domain `wormhole/v1/key-copy` followed by length-prefixed fields: workspace
UUID, copied key UUID/version, holder UUID/version, and issuer UUID/version.
UUIDs are raw 16 bytes; versions and length prefixes are big-endian uint32.

The issuer Ed25519 signature covers domain `wormhole/v1/key-copy-signature` and
length-prefixed HPKE info, envelope format and suite (each big-endian uint16),
encapsulated key and ciphertext. `OpenKeyCopy` requires the exact 48-byte
ciphertext, validates the envelope, and verifies this signature before HPKE
decryption. Re-signing substituted metadata does not change the context under
which the existing ciphertext was encrypted. Unknown envelope versions fail
closed. Recipients use canonical X25519 public-key encodings, and the HPKE
implementation rejects low-order points.

`RewrapKeyCopy` opens a verified source copy and wraps it for a different holder,
preserving the workspace and copied key reference. The new holder and issuer
must come from an authenticated rekey certificate. The temporary plaintext key
and derived signing-key copy are wiped on exit, including failure. The caller
must commit the complete replacement set in one transaction before retiring the
bootstrap; a successful operation on one copy does not prove that the set is
complete or that an invite has been consumed.

Tests cover an actual bootstrap-to-final-user rekey and rewrap, old-key rejection
on the replacement, new-key rejection on the source, every context coordinate,
re-signed context substitution, wrong issuer, ciphertext tampering, malformed
envelopes, invalid key references, SQL version bounds, low-order recipients and
invalid source/destination failure paths. Secret output remains native-only;
callers of `OpenKeyCopy` own its returned temporary key and must wipe it.

## Preparing the replacement set

`PrepareInviteRewrap` combines the fresh-key proof with replacement of the whole
expected copy set. Its native caller must first authenticate the bootstrap and
obtain a complete, authenticated graph plus certified issuer keys. The expected
bindings are separate from ciphertext; equal array lengths alone cannot prove
that an untrusted server supplied every copy.

The operation requires matching counts, distinct copied-key references, the
expected workspace and bootstrap holder, valid envelopes, and a certified issuer
for every entry. It accepts at most 1024 copies per prepared set and fails closed
above that bound. An independently authenticated empty graph is allowed for a
user without grants. It generates one final key pair, then uses that same holder
and issuer for every replacement. Cancellation and any failed source verification
return no plan, wipe the newly generated private keys, and leave the source
bootstrap available for a retry. Context cancellation is checked before work,
between copies and before returning success.

The resulting `InviteRewrapPlan` contains temporary private keys excluded from
JSON, the public transition proof and all replacement bindings/ciphertexts.
`Wipe` clears its private keys and retires the public plan fields. This remains a
preparation step: the protected native owner and PostgreSQL transaction must
still enforce current invitation expiry, single-use redemption, completeness
against authoritative state, atomic publication and bootstrap retirement. No
server or app Join workflow calls this API yet.
