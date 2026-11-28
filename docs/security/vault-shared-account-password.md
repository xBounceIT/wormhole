# Native shared-account password derivation

`sharedpg.DeriveAccountMaster` derives an account master from borrowed password and
ASK bytes, using authenticated enrollment/invitation facts and a verified policy.
It performs no network or filesystem operation. Its inputs are native backend
values, not renderer assertions or unauthenticated server suggestions.

Before allocating Argon2 memory it checks the workspace identity, immutable
canonical login name, password/ASK bounds, policy validity, effective profile and
KDF floor. It uses the existing `SharedSalt` and serialized Argon2id gate, then
`MixAccountSecret` with the authenticated ASK requirement. Hardened administrators
and custodians require an ASK; Paranoid requires it for everyone. An optional ASK
cannot silently disappear or be inferred from a supplied input field.

The resulting `AccountMaster` owns the mixed master in a 32-byte native memory
buffer. Hardened/Paranoid require locked pages before expensive derivation starts.
Default/Standard callers inspect `Locked` for the existing memory-lock warning.
Temporary password-derived and mixed heap buffers are wiped. Cancellation is
checked before work, by the shared Argon2 gate, after derivation and after copying
the result. Borrowed password/ASK bytes remain the responsibility of their input
owner and must be wiped after return.

The owner has no secret serialization or raw-buffer accessor. `Use` borrows its
master together with the preset/ASK facts established by derivation; the callback
must not retain the slice or recursively invoke `Use`, `Locked` or `Close` on that
owner. The underlying native buffer serializes use against closing. Always call
`Close`, including on a nonnil owner returned with `ErrAccountMasterCleanup`.
Unconfirmed native release retains a retired, wiped owner solely for cleanup retry.

`sharedAdmissionController.OpenAccount` consumes this owner for native admission
and account unlock. It rejects a different workspace before network access. The
admission path checks the owner's derivation against the authenticated cached
policy and effective OS/user floor **before opening PostgreSQL**, then checks the
new signed server policy before publishing admission. A stronger server policy is
persisted before denial. This prevents a stale, weaker derivation from reaching
the network when the local trusted policy already requires more.

After successful unlock the controller owns only its protected trust root and
private account pair; the caller can close the master immediately. Failed unlock
retires the controller. `RecoverAccount` uses the same native owner and established
derivation facts for [password recovery](vault-shared-password-recovery.md), with
the same remote-outcome/local-error distinction. Recovery also checks the cached
KDF/ASK floor before opening the connection.

Tests exercise real Argon2id/ASK derivation, native memory ownership, serialization
resistance, input preservation, malformed identities/factors, profile/KDF floors,
required locked pages, cancellation and failed cleanup. Controller tests derive
real masters, seal matching account capsules and verify login/unlock and both
recovery modes with real encrypted trust files and a typed session probe. They
also assert that weak derivation never reaches the network and that stronger
server ASK policy survives denial.

This does not implement the application password dialog or persistent enrollment
format. Authentication of enrollment/KDF metadata, root lifecycle, and access from
another device after a remote password change remain prerequisites for the full
shared-workspace workflow. The native APIs do not make that workflow release-ready.
