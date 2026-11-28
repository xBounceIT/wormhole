# Organisation-certified user keys

`vault.UserKeyCertificate` binds one X25519 encryption key or Ed25519 signing key
to a workspace, user, key ID/version, suite, certificate revision and organisation
signer ID/version. It grants neither administrator status nor a Write capability.

Version 1 signs fixed-order JSON with the signature field set to null, using the
existing length-prefixed canonical encoding and domain
`wormhole/v1/user-key-certificate`. There are no maps, floating-point numbers or
algorithm fallback. Key/signer versions are positive PostgreSQL integers; revision
is a positive bigint. IDs are nonzero; a user key cannot be its own organisation
signer. Suite interpretation is scoped to key kind: 2 for X25519/HPKE encryption,
1 for Ed25519 signing. Encryption keys receive the existing canonical X25519 and
low-order checks. Ed25519 public keys must be exactly 32 bytes.

`SignUserKeyCertificate` validates, signs and returns independently owned public-key
and signature buffers. Its native admin caller must first verify enrollment/rekey
possession and authorise issuance. The primitive does not make those decisions.

`VerifyUserKeyCertificate` requires expected workspace, user, key reference, kind,
organisation signer, pinned organisation public key and minimum certificate revision
from independent trusted state. It verifies the signature before accepting the
revision. A valid signature under a substituted organisation key or a certificate
for another identity/key version is insufficient.

`OpenCertifiedUserKeys` verifies both certificates before AEAD opening. Decrypted
private keys must also reproduce both certified public keys. An authentic
certificate for a different public key cannot open a mismatched capsule. The caller
owns and must wipe returned private material; inputs and organisation pins are borrowed.

Certificate revision floors alone do not establish revocation freshness. Callers
must authenticate current graph/key high-water marks and the wrapping revision,
and verify KDF/ASK policy before deriving the master. These primitives do not fetch
or persist trust state. PostgreSQL provides [atomic certificate retrieval](vault-shared-account-keys.md).
Enrollment/reset issuance,
durable rollback floors and application unlock orchestration remain to be connected.
There is no renderer API for certificates, ciphertext or private keys.

Tests cover both key kinds, certified capsule round trips, stale revision floors,
swapped identities/key kinds/signers, modified public keys/signatures, substituted
organisation pins, wrong masters, signed-but-mismatched public keys, buffer ownership,
unsupported formats/suites, malformed keys and numeric limits.
