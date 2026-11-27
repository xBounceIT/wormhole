# Protected TLS sequence and digest

Local shared-workspace trust format 4 stores a positive `tlsSequence` and a
32-byte `tlsDigest` alongside the existing authenticated policy and optional
account state. The digest is SHA-256 of the canonical signed TLS bundle. The
full public bundle stays outside this small protected record; the 32 KiB trust
file and 128 KiB password-transition limits remain unchanged.

Formats 2 and 3 remain readable with their original canonical encoding, and
cannot contain TLS fields. Format 4 requires TLS fields and a canonical UUID
organisation signer. It can precede account unlock: missing account state does
not become an account authorization merely because TLS trust is present.

`TrustState.AdvanceTLS` accepts a verified bundle only under the state's workspace,
organisation signing reference and public key. It rejects lower sequences and
different digests at the same sequence, increments the local revision for a new
sequence and copies retained state. `ValidateAdvance` prevents any writer from
erasing or rolling back a TLS floor, even while advancing policy/account fields.
Profile and account updates preserve format 4 and copy its digest.

`TrustState.VerifyTLS` verifies a separately supplied canonical bundle against
the protected sequence/digest and pinned organisation. A newer result must still
be advanced and durably written before use. For Verified TLS, `PrepareTransport`
requires a bundle matching the exact protected sequence and digest; raw CA PEM
cannot bypass an installed TLS floor. Existing explicitly selected Default
profile non-Verified modes retain their existing profile rules; TLS fields are
not erased by such a selection.

The admission controller advances and writes the floor before its first network
connection. It uses the existing locked compare-and-swap writer and authenticated
readback for uncertain durability. Even if later runtime/admission checks fail,
the authenticated observation remains recorded. Storage conflict or unconfirmed
durability prevents exchanging a login proof.

During password recovery, `ObserveTLS` writes the same observation into the
pending journal under the new root before network access. Both promotion after
confirmed commit and abort after independently proven noncommit retain the TLS
floor. Password-root preparation supports account-bearing format-4 states;
immutable preparation records and monotonic observation checks remain enforced.

Tests cover format upgrade and encrypted reopen, idempotence, revision overflow,
foreign organisation/workspace, malformed fields, rollback/equivocation, raw-CA
bypass, premature use of a newer bundle, profile/account updates and cloned
digests. Controller tests verify persistence before dialing, lock/sync failures,
uncertain durability confirmation and TLS floors surviving account unlock and
both password-recovery outcomes.

The native caller supplies a verified public bundle for initial publication; the
[public cache](vault-tls-bundle-cache.md) now supports later loading from the
protected digest, including password recovery. Coordinated retention preserves
pending recovery copies. WorkspaceMeta
publication, initial enrollment/provisioning and invalidation of already-open
sessions on live trust changes remain required integration work. Restoring all
valid old protected state and its independent
revision floor is not detectable by encryption alone.
