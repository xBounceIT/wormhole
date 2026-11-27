# Native shared account-key unlock

`sharedAdmissionController.Unlock` extends the native owner after successful
transport admission. `Admitted()` and `Unlocked()` are separate statuses. Neither
grants tree access, secret-use permissions or renderer access to keys.

The native [account password owner](vault-shared-account-password.md) now derives
and retains that master in native memory. `OpenAccount` combines admission and
unlock using the owner's established preset/ASK facts, including a cached-policy
check before connecting. Application password entry and enrollment remain separate.

The native password flow supplies the borrowed 32-byte account master after ASK
mixing, its KDF preset and whether it used an ASK. These derivation facts must never
come from renderer assertions. Admission retains only a SHA-256 commitment of the
derived login material, alongside its protected trust root. Unlock derives the login
material from the supplied master and compares the commitment in constant time;
the temporary derivation is wiped. A different master cannot unlock this admission.

Unlock holds the owner's cancellation-aware gate and has a 60-second limit:

1. Reload authenticated trust and reject an external revision change since admission.
2. Check the actual derivation against the signed workspace KDF/ASK requirements
   and the effective runtime profile retained from admission, including OS/user
   floors. For example, effective Standard refuses `kdf-low` even when a Default
   workspace approved it. Hardened/Paranoid remain unsupported at admission.
3. Retrieve and verify signed account state, persist or durably confirm its trust
   advance, then deny a revoked account. An initial format-2 upgrade uses the schema's
   universal wrapping lower bound of 1, never an unverified server revision.
4. Retrieve the consistent state/certificates/capsule response. Recheck and persist
   its state, including any newer revocation observed between reads. Check its
   KDF/ASK metadata against the native derivation.
5. Verify current key selection, certificate signatures/revisions and the encrypted
   private pair through `OpenCurrentUserKeys`. Only successful opening may advance
   the wrapping floor above its previously authenticated value.
6. Persist/confirm that floor before copying the private pair into a 64-byte native
   secure-memory buffer. Wipe the temporary pair and publish `Unlocked` only while
   the operation, owner and session remain live.

Uncertain file replacement receives one exact-state durability-confirmation attempt.
Continued uncertainty denies unlock and retires the owner, even if the new file can
already be read. Invalid arguments, cancelled preflight and repeated unlock calls
do not alter an existing owner; failures after a new attempt starts withdraw
admission and clean up. A cleanup failure preserves ownership for explicit `Close`
retries. The caller remains responsible for wiping its borrowed master.

Close/invalidation withdraws status immediately, cancels in-flight reads and retires
private-key memory before the trust root and session. It also clears the login
commitment. Default/Standard report a memory-lock warning if any retained native
allocation could not lock its pages. No public key-buffer accessor or IPC route is
introduced by this change.

Controller tests use real encrypted files and native memory with an injected typed
session. They cover ordering, private-key ownership, cancellation, cleanup retries,
revocations at both reads, wrong master, KDF/ASK policy, malformed material, tampered
ciphertext, external trust changes and final-floor durability failures/recovery.
Real PostgreSQL cryptographic retrieval/opening tests exercise the underlying
transport separately; a full running-app shared login is not yet verified.

Application enrollment/password entry, provisioning/admin state changes, tree/grant
authorization, ongoing change/idle monitoring and protocol key use remain unwired.
The verification path is shared with the native
[password-change controller](vault-shared-password-change.md), which now stages
and promotes the durable local trust-root transition. Native
[outcome reconciliation](vault-shared-password-recovery.md) is available; application
password entry remains pending. The native unlock API does not make
the complete shared workspace ready for release.
