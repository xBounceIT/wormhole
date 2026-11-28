# Shared workspace policy and account trust state

Issue #495 remains incomplete. Native primitives now encode, encrypt, read and
atomically advance device-local policy trust. The native
[admission controller](vault-shared-admission-controller.md) uses these primitives;
enrollment, unlock and application UI integration remain pending. They do not create
an offline tree or cache workspace secrets.

`sharedpg.NewTrustState` verifies the enrollment profile against an independently
confirmed organisation signing key. The state contains workspace/user/device IDs,
the pinned signer identity and key version/public key, the accepted policy
sequence, a SHA-256 digest and copy of the canonical signed profile, and a local revision.
It contains no private key or login password. It is not the server TLS trust bundle;
authenticated endpoint/CA enrollment remains separate work.

`TrustState.Advance` reuses the existing pin to authenticate the next profile. It
rejects older sequences and different signed content at the same sequence. An
unchanged profile leaves the revision unchanged; a newer profile increments it
without changing the pin. Organisation key rotation requires a separate authorized
transition, not an ordinary policy update. Public-key and digest buffers returned
from transitions do not alias the old state.

`SealTrustState` derives a dedicated `wormhole/v1/shared-trust` subkey from the
borrowed unlocked root and encrypts canonical JSON with the existing vault AES-GCM
envelope. AAD binds the workspace, user, device and expected key ID/version. The
root and binding are provided by authenticated device enrollment, never discovered
from the file. Temporary derived keys and plaintext buffers are wiped. Documents
are bounded to 32 KiB; noncanonical, malformed, substituted or tampered documents
fail closed. The root key is not retained by these functions or written to disk.

The backend's native-only `readSharedTrustFile` and `writeSharedTrustFile` use an
application-selected absolute path. Reads require a regular file and a bounded
read. Writes use the existing exclusive file lock, private temporary-file writer,
file sync and platform atomic replacement/directory durability mechanisms. They
authenticate existing state before comparing revisions, preserve signer pins,
and validate a monotonic policy/account transition. Missing or damaged state is never
reset during an update. Initial creation is reserved for authenticated enrollment.
No arbitrary path or trust mutation is exposed through renderer IPC.

A failure after replacement returns a distinct uncertain-commit error.
`confirmSharedTrustFile` authenticates and compares the entire expected record
under the exclusive lock, then publishes it again through the durable writer.
It cannot create missing state, modify a pin/digest/counter or confirm a different
record. Continued sync failure still returns uncertainty. Successful confirmation
establishes durability without advancing the revision; readback alone does not.
A successful write or confirmation does not activate a workspace.

Trust-state format 2 adds the cached signed document. The earlier experimental
format 1 is rejected, with no unsigned default or automatic reset. Neither format
has been exposed in an application workflow. The native admission controller now
uses format 2. `TrustState.Policy` re-verifies the
cached signature, exact sequence, workspace and digest. `PrepareTransport` checks
the client's API against this authenticated policy and applies the strictest
workspace/OS/user/caller floor before validating connection settings. Standard+
cannot send a login proof over plaintext or unverified TLS through these prepared
settings. It copies endpoints and CA bytes to prevent caller-buffer aliasing.
The receiver must have been authenticated by `OpenTrustState` or independently
confirmed enrollment; a signature cannot establish the source of an arbitrary pin.
The native admission controller invokes this preflight before opening the connection.
This remains transport-only enforcement; full Hardened/Paranoid runtime behavior
and authenticated endpoint/CA provisioning are separate work.

The reader enforces a caller-provided minimum local revision, and writes prevent
lost updates and decreasing policy sequences. These controls protect against a
server replaying an older profile while the local state is intact. Encryption
cannot detect restoration of both an older valid file and its external revision
floor. This implementation does not claim a hardware monotonic counter, and the
protected enrollment and application revision lifecycle remain pending.

Format 3 adds the full organisation-signed current account-key state and the
highest verified password-wrapping revision. Format 2 remains readable with its
original canonical encoding; its new fields must be absent. It cannot authorize
account-key opening. `AdvanceAccount` explicitly upgrades it after verifying a
signed account state against the existing organisation pin, which must identify a
canonical UUID key. There is no default active account, unsigned migration or pin
replacement. Format 3 requires a complete valid signed account state on every read,
including during cached policy validation.

`AdvanceAccount` rejects decreasing account sequences and wrapping revisions,
different signed records at the same sequence, lower versions of the same key ID,
and lower certificate floors for the same key reference. New key IDs may begin
their own version/revision history. An unchanged state/floor needs no write; a real
advance increments the local revision. The complete signed record, rather than
just its sequence, is retained for same-sequence equivocation checks.

Authentic revocations are accepted as trust updates and must be persisted before
denying unlock. A later policy update preserves that account state and its floors.
The file writer independently runs `ValidateAdvance`, so constructing a candidate
outside these transition helpers cannot erase account state, return to format 2,
reduce floors or rewrite a policy/account record at the same sequence. Exact-state
uncertain-commit confirmation includes the entire account record as well.

`AccountTrust` returns independent copies of the pinned organisation key and the
stored sequence/wrapping floors. Callers must still pass each incoming state through
`AdvanceAccount` before acting, to check same-sequence equivocation, and persist
changes before publishing unlocked state. For active accounts, wrapping revisions
must first be authenticated by successful key opening; a revocation can retain the
existing wrapping floor. The controller now performs this through its explicit
[native Unlock method](vault-shared-account-unlock.md), separately from transport
admission. PostgreSQL signed-state retrieval is available through the
[schema-8 API](vault-shared-account-keys.md); application wiring and the
password-root orchestration remain pending. The
[local transition primitive](vault-shared-root-transition.md) now supports staging,
promotion and recovery; its journal blocks ordinary trust writes until reconciled.

Tests exercise ciphertext round trips, identity/key substitution, authenticated
malformed records, duplicate fields, sequence rollback/equivocation,
revision overflow, non-aliasing, missing/corrupt-file handling, pin preservation,
concurrent writers, and uncertain durability with authenticated readback. Numerical
coverage is measured per changed function; defensive marshal failures for bounded
typed records are not forced merely to increase coverage.
