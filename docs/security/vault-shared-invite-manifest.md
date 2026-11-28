# Authenticated invite graph

An invite's prepared key-copy set is described by an organisation-signed
`InviteManifest`. This replaces reliance on an unauthenticated list of expected
bindings and issuer public keys when preparing a join.

The version 1 manifest contains the complete `InviteContext`, a positive signed
64-bit graph revision, expiry, bootstrap public encryption/signing keys, ordered
copy bindings, and the public Ed25519 keys of exactly the issuers used by those
copies. It contains no organisation public key: that trust root must come from
the bootstrap authenticated with the separate code and checked against the
invitation fingerprint. Bootstrap X25519 public keys reject noncanonical and
low-order points. Copies must belong to the expected workspace and bootstrap
holder; duplicate key references, duplicate/missing/unused issuers and invalid
references are rejected. Both lists are bounded at 1024 entries.

The organisation signs the canonical JSON document with `signature` set to null,
wrapped with the existing length-prefixed `wormhole/v1/invite-manifest` domain.
Encoding uses explicit camel-case fields and typed integers/UUIDs/byte arrays.
The wire document is bounded at 1 MiB and must exactly match its canonical
re-encoding, rejecting unknown, duplicate, missing, case-folded or ambiguous
fields. Decoding checks shape; verification separately authenticates the expected
context, organisation key, expiry and caller-supplied minimum revision. A forged
old revision reports authentication failure, not an authenticated rollback.

`Invitation.PrepareRewrap` opens the bootstrap with the code, verifies the
organisation fingerprint, authenticates the manifest under that organisation
key, and matches both bootstrap public keys against the decrypted private
material. Only then are the manifest's list and issuers passed to the complete
rewrap operation. Bootstrap plaintext is wiped on every exit. An omitted copy or
any failed verification returns no plan. An organisation-signed empty set permits
users without grants.

A successful plan retains `sourceManifestRevision` and SHA-256 of the exact signed
wire manifest as `sourceManifestDigest`. Wiping a plan clears these commit
coordinates along with its keys and replacement set. Schema migration v3 stores
the bounded signed manifest and positive revision on each invite, and computes
its digest with PostgreSQL's built-in `sha256` generated column. This requires
no extension and prevents a normal update from supplying a mismatching digest.

The future redemption transaction must compare that revision/digest with the
locked authoritative invitation, enforce expiry and single use, and publish the
complete replacement set atomically. A digest alone is not authentication, and
a revision floor detects only rollbacks below a floor the caller already trusts.
This does not solve rollback of both external floor and stored state, or a
trusted organisation equivocating at the same revision. No enrollment role or
Join UI is enabled by these primitives.
