# Signed workspace TLS trust bundle

`internal/sharedpg/tls_trust.go` authenticates the workspace TLS roots, exact
endpoint host set and certificate revocations using the independently pinned
organisation signing key. Native connection/session setup accepts a verified
snapshot through `Settings.TLSBundle`. The controller now persists the
[protected sequence and digest](vault-tls-protected-state.md) before connection;
[public-bundle caching](vault-tls-bundle-cache.md) supports restart and password
recovery with coordinated retention; enrollment remains incomplete.

The version-1 document contains workspace UUID, organisation signer key reference,
positive sequence, DER CA list, canonical host list and revoked issuer-SPKI/serial
pairs. The signature domain is `wormhole/v1/tls-trust` followed by a NUL and the
canonical JSON body with a null signature. Signed encodings are strictly
canonical: unknown or duplicate JSON fields, alternate whitespace/encoding,
trailing data and unsorted/duplicate list entries are rejected.

Version 2 uses the domain `wormhole/v2/tls-trust` and adds a signed
`workspaceCa` record. It identifies the workspace issuing CA by the digest of
its DER certificate and the reference of its wrapped key. An overlap also
identifies the previous root and carries the public DER certificate prepared
from the server CSR. Every previously approved host and revocation is retained
through staging and retirement. A completed rotation has only the new root.
Version-1 bundles retain their original encoding and verification rules.

Limits are eight CA certificates (32 KiB each, 128 KiB combined), 64 hosts and
4096 revocations, with a 1 MiB document cap. CA entries must parse as CA
certificates with certificate-signing usage. Provider CAs are supported; validity,
chain usage, name constraints and hostname validation are enforced by Go TLS at
connection time. DNS hosts are lowercase, IPs canonical and unmapped; wildcards,
zones and trailing dots are not accepted.

`VerifyTLSTrustBundle` requires `TLSTrustPin` from independent enrollment/protected
storage, never from the response itself. The minimum sequence must be positive.
At enrollment only, the digest may be absent when the minimum sequence is
independently pinned. Once a document has been observed, persist its sequence
and canonical encoding digest. A different authenticated document at the same
sequence is rejected, as is a lower sequence.

The returned `VerifiedTLSBundle` owns a private snapshot. `Advance` retains the
organisation/workspace pin and checks a new signed document against the current
sequence and digest. `Encode` and `Pin` return independent copies for durable
storage. Callers must durably persist both before publishing the new bundle to
connection owners. No freshness beyond the supplied floor or protection against
restoring all local state is claimed.

`VerifiedTLSBundle.Config` accepts explicit Verified TLS settings without an
additional caller-supplied CA PEM. It checks every endpoint against the exact
host set and builds the existing pgx configuration with only the signed roots.
Normal chain and hostname verification remain enabled; SCRAM authentication and
required channel binding remain unchanged. Every fallback receives a
`VerifyConnection` callback, which rejects revoked certificates and Ed25519
server keys after normal verification. The callback also runs on TLS resumption.

The ordinary `Config` factory dispatches to the verified bundle when
`Settings.TLSBundle` is present. Consequently `Connect` and both connections
opened by `Session.Open` retain these checks. The field is excluded from JSON:
only native code can supply a verified snapshot. `TrustState.PrepareTransport`
also matches its workspace, organisation signer reference and public key against
the authenticated cached policy before any login proof is exchanged. This
identity check is supplemented by exact sequence/digest matching once format-4
protected TLS state has been installed.

A revocation uses the SHA-256 digest of the issuing public-key information and
the positive lowercase hexadecimal certificate serial (maximum 20 octets,
without leading zeros). Renewing the issuer certificate with the same key cannot
erase a revocation. Revocation matching covers each verified chain; for a final
trust anchor, its own key is used. To retire a non-self-signed trust anchor,
remove it from the signed CA list. No OS trust roots or OS trust-store writes
are used.

Rotation publishes an overlapping CA set, then removes the retired CA at a
higher sequence, retaining the organisation pin and requiring no new invite.
Configurations already returned by `Config` remain snapshots: the controller
invalidates the old owner when it persists a new bundle. The [workspace CA
flow](vault-workspace-ca.md) publishes each transition and the audit event in
one database transaction.

An admitted device can export the current canonical signed document as a
`.whtls` file. An enrolled device that missed a rotation can select the file
in protected sign-in. After opening the existing password slot, Go checks the
signature and sequence against the independently authenticated device trust.
It verifies compatibility with the sealed transport configuration and saves the
bundle, protected floor and OS-protected startup anchor before connecting.
Equal documents can complete an interrupted import. Older sequences, equal
sequences with a different digest and other workspace identities are rejected.

Tests include canonical-codec attacks, foreign pins, tampering, equivocation,
rollback, mutation isolation, malformed bounds and real localhost TLS handshakes
for valid/revoked certificates, issuer renewal, exact fallback hosts, CA overlap
and retirement, and rejection of Ed25519 server certificates. Negative handshake
tests check the revocation/key-policy error specifically, not merely a timeout.
