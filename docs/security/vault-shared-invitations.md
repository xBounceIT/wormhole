# Shared workspace invitation format

The native `internal/sharedpg` codec defines public enrollment coordinates. It
does not provision users, redeem codes, activate a workspace, or implement the
Join UI. Enrollment must authenticate the prepared bootstrap material before
choosing a password or accepting an organisation key.

Native bootstrap primitives in `internal/vault` now seal and open that material.
`Invitation.OpenBootstrap` validates the current expiry and expected workspace and
login, then authenticates the bootstrap and checks its organisation fingerprint.
It returns no private key on either failure. This is a cryptographic step, not a
server-side redemption or permission grant.

The clipboard and invite-file content use the same token:

```text
WHINV1-<unpadded base64url canonical JSON>.<lowercase SHA-256 hex>
```

The checksum covers the prefix and encoded payload, excluding the period and
checksum. It detects transcription errors; anyone can recompute it. It is not a
signature. The one-time code must arrive separately and has no field in this
format. An unknown field, including a code field, invalidates the document.

Canonical JSON uses the field order defined by `Invitation`, explicit fields,
Go JSON string escaping, canonical UUID text, and standard padded base64 for
byte arrays. Fields are `formatVersion` (1), `workspaceId`, `loginName`,
`endpoints` (objects with `host` and `port`), `database`, `tls`, `caPem`,
`organisationFingerprint`, and `expiresAt` (Unix seconds). An absent CA uses
`null` or the empty base64 string; the field itself, endpoints and the fingerprint
cannot be omitted. Encoding
and decoding share the transport validator, which does not read files, inspect
PostgreSQL environment variables, or connect to a server.

The legacy format fits within 384 KiB of decoded JSON, with eight endpoints,
256 KiB of CA PEM, 256 UTF-8
bytes for the immutable normalized login, and a 32-byte organisation fingerprint.
Hostnames, ports, database identifiers and TLS modes follow the native transport
contract. The complete input is bounded before decoding. Only outer ASCII space,
tab, CR and LF are trimmed; base64, checksum and JSON must otherwise be canonical.
The invite is expired at its exact expiry second. Device-role validity and
single-use redemption remain separate server-side enrollment requirements.

The fingerprint is SHA-256 of the raw 32-byte Ed25519 organisation public key.
After the separate code successfully authenticates and opens bootstrap material,
`CheckOrganisationKey` compares that material's key with the fingerprint and
rechecks expiry. A key merely downloaded from an unauthenticated server must not
be passed off as authenticated bootstrap material. Public invite transport
settings also cannot override the signed security profile or local policy floor.

Tests cover round trips, ambient service-file independence, supported TLS modes,
expiry boundaries, wrong keys, malformed coordinates, Unicode normalization,
duplicate/unknown fields, invalid JSON/base64, recomputed checksums over malformed
documents, oversized input and inner newlines. Transport regression tests retain
the real PostgreSQL SCRAM and TLS checks.

## Signed TLS enrollment invitation (WHINV3)

`WHINV3-<unpadded base64url canonical JSON>.<lowercase SHA-256 hex>` is format
version 3. It retains the version 2 enrollment coordinates and requires Verified
TLS, an empty `caPem`, and a `tlsIdentity` object containing `organisation` (raw
Ed25519 public key, padded base64) and `bundle` (canonical TLS trust-bundle JSON).
Versions 1 and 2 reject this new field; version 3 cannot omit it or fall back to
Off, Encrypted, historical CA PEM or system roots. Prefix and version must agree.

The decoded document limit is 1 MiB + 384 KiB. The embedded bundle retains its
existing 1 MiB bound, eight CA and 4,096 revocation bounds. Keeping it as nested
canonical JSON avoids an extra base64 layer; token, protected IPC, native stdin
and continuation limits remain explicitly bounded. Large revocation-list tests
exercise documents above the old legacy limit.

Offline parsing checks key/fingerprint consistency, the organisation signature,
workspace identity, canonical bundle shape and exact permitted-host membership.
It does not read ambient PostgreSQL settings or contact a server. This is public
discovery material: the invite checksum and a self-consistent public key do not
establish organisation authority. The first temporary SCRAM connection applies
only these signed roots, host rules and revocations, with required channel
binding. No account password, master or private account key is released by it.

After the separate code opens the bootstrap, certification must bind the same
organisation public key AND signer key ID/version to the TLS proof. A valid TLS
signature from the right public key under a substituted signer ID is refused
before account derivation or complete-copy rewrap. The application then obtains
the bundle under this authenticated identity and passes it to the existing join
coordinator. That coordinator records the sequence/digest observation, public
signed cache and encrypted transport/pending state in the atomic initial
checkpoint before the single SQL submission.

V3 issuance uses `Invitation.SealBootstrap`, with a fresh invite ID and code. The
unchanged 97-byte bootstrap plaintext and frozen AES-GCM envelope acquire an
additional expected AAD binding: append `/tls-v1/` and the lowercase hex SHA-256
digest to the legacy context's field. The digest hashes ASCII
`wormhole/v1/invite-tls`, the fixed 32-byte organisation public key, then the
canonical bundle JSON. No legacy envelope is stored for that issuance. Stripping
the proof and recomputing a valid WHINV2 token therefore fails bootstrap AEAD;
substituting another correctly signed bundle also fails. There is no legacy-open
retry. Reissuing/converting an already-issued legacy invite requires fresh ID and
code; retaining an old legacy envelope and reusing its code would retain its
original authority.

Continuation loads its current authenticated TLS floor/cache, which can replace
the invitation's historical roots. The historical invite is never allowed to
override a later sequence/digest observation. Ordinary reopening uses the same
protected managed transport. These primitives do not create the deployment
wizard, generate a CA for a production server or complete the CA-rotation UI.

## Bootstrap envelope

The separate code is exactly 128 random bits. The native caller must obtain it
from the operating-system cryptographic random source; these APIs accept raw
bytes, not a password, a decimal PIN, or a truncated text encoding. The code is
never part of the invitation token or stored in the bootstrap envelope.

HKDF-SHA256 derives independent 32-byte keys using `wormhole/v1/invite-login` and
`wormhole/v1/invite-unlock`. The salt is SHA-256 of the ASCII domain
`wormhole/v1/invite-context` followed by length-prefixed fields: workspace UUID,
user UUID, invite UUID, bootstrap key UUID (each raw 16 bytes), key version
(big-endian uint32), and normalized UTF-8 login. Each prefix is a big-endian
uint32 byte count. Reissuing an invite requires a fresh invite UUID.

The existing AES-256-GCM vault envelope binds the workspace, table `Invites`,
invite ID as owner, lowercase hex salt as field, and bootstrap key ID/version.
Plaintext is exactly 97 bytes: format byte `1`, 32-byte X25519 private input,
32-byte Ed25519 seed, and 32-byte organisation Ed25519 public key. Both private
inputs are independently generated using `crypto/rand`. Envelope length is
checked before decryption; the organisation fingerprint is checked only after
AEAD authentication. The login key cannot open the envelope.

Temporary derived keys and plaintext copies are wiped on all exits. Returned
bootstrap material is native-only, excluded from JSON serialization, and must be
wiped by its owner on success, failure or cancellation. It is not a long-lived
key store; keeping it beyond an immediate native operation requires secure-memory
ownership. These operations do not change the existing 32-byte `DeriveKey`
contract for vault roots.

## Bootstrap-signed rekey proof

After authenticating the bootstrap, `PrepareInviteRekey` generates independent
random X25519 private input and Ed25519 seed for the final user keys. Encryption
and signing keys receive distinct fresh UUIDs, both at version 1, matching the
separate `user-enc` and `user-sign` entries in `Keys`. It returns temporary native
`UserKeys` and a public `InviteRekeyProof`; private fields are excluded from JSON.

The bootstrap Ed25519 key signs a length-prefixed record with domain
`wormhole/v1/invite-rekey`: the invite-context salt described above, uint16 format
version, encryption key UUID, signing key UUID, uint32 key version, X25519 public
key and Ed25519 public key. Integer fields are big-endian. Verification receives
the expected invite context and previously authenticated bootstrap public keys
independently. A proof cannot select its own signer.

Verification rejects changed coordinates, identifiers or public keys, invalid
signatures, missing or equal new key IDs, reused bootstrap public keys, low-order
X25519 points and noncanonical X25519 representations. In particular, ignoring
the high bit as X25519 normally permits would allow a bytewise reuse check to be
bypassed; this format requires the unique representative below `2^255-19`.

The returned key material must be wiped by its owner. Bootstrap keys deliberately
remain available until their issued key copies have been rewrapped. This proof
is a transition certificate, not an organisation-admin certificate or a database
authorization grant. Server-side single-use enforcement, attempts, expiry,
transactional redemption, rewrapping issued key copies and deletion of the
bootstrap remain required before a usable Join flow can be enabled.
