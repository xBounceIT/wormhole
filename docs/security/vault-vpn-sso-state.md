# Personal VPN SSO archive custody

Issue [#495](https://github.com/xBounceIT/wormhole/issues/495) requires persistent
VPN provider SSO storage to be vault-managed at Standard. The native Go owner now
has archive custody in `internal/localvault/vpn_sso.go`. The local Fortinet SSL
and IPsec SAML flows use an [owning native browser session](vault-vpn-browser.md)
to restore/capture supported storage in volatile partitions, then clear each
attempt. Unsupported storage, complete live shared deployment validation and other
roadmap work remain. Shared SSL/IPsec uses personal/device custody with
independent source authorization and enrolled final keys (deployment migration42).

The [native Go transfer state machine](vault-vpn-sso-transfer.md) now connects
sealed chunk restore/capture to this custody. It requires positive restore
acknowledgement, retains only ciphertext between requests, and checks the
resident source floor before releasing more data. Local source admission,
recipient/storage adapters, signed slot observations and RPC wiring are connected.
The local whole-database plus signed-slot replay limitation remains documented.

The [fallback source path](vault-tunnel-fallback.md) also admits retained SSL SSO
from an exact authenticated IPsec-to-SSL pair. Every local archive operation
rechecks the encrypted primary reference and SSL target; shared operations use a
fresh independently audited fallback release and personal custody. Both source
identities/configuration versions participate in cache identity. Original source
request IDs and active SSL challenge IDs remain separate through the main-only
browser adapters. Final local commit responses revalidate sources after protected
checkpoint publication and suppress newly stale receipts. Automatic broker
fallback startup remains unfinished.

## Storage and ownership

The receiver is the user's personal local vault owner, including in shared mode.
It must never be a PostgreSQL workspace key or a shared credential. The native
resolver must supply the source workspace/file, tunnel, local account, provider
kind, configuration revision, gateway origin, realm, complete upstream route
digest and TLS trust digest. These fields select an independent archive scope;
they do not grant Use or authenticate a caller. Native route admission must still
precede archive access. No renderer bridge or vault wire operation exposes this
primitive.

The archive stays opaque mutable bytes. No cookie-only subset is assumed, and
this primitive does not define a browser serializer. The native serializer
versions its archive, captures/restores supported provider storage and validates
its contents; the completion handoff stays separate. In particular, a
restored `SVPNCOOKIE` must never replace fresh issuer/commit proof. Existing
encrypted migration archives are not yet connected to this runtime adapter.

The encrypted local-state manifest binds every chunk and retired chunk version.
Inside it, a 48-byte `VSS1` header binds the archive to its full binding digest,
durable revision and exact byte length. The total record is bounded to 64 MiB.
No archive, profile directory or plaintext temporary file is written outside the
vault. Borrowed reads and consumed capture buffers are wiped on success, error
and cancellation; ordinary JSON serialization of a snapshot is refused.

## Revisions and failure behavior

`OpenVPNSSO` borrows the current archive and publishes an attempt reservation only
after successful acknowledgement. The reservation keeps the immutable binding,
source checkpoint, policy sequence and a five-minute expiry. There are at most
32 active attempts. `SaveVPNSSO` accepts only that matching attempt, rechecks the
authenticated effective policy and refuses a changed source or policy. A durable
commit consumes the reservation. Failed writes retain it for a matching retry.
Two concurrent logins therefore cannot silently overwrite one another.

`DeleteVPNSSO` leaves an authenticated tombstone. Already-open attempts cannot
resurrect the deleted snapshot; an explicitly opened new login can advance its
revision. A matching repeated deletion is idempotent. Its future native
controller must require fresh authentication before invoking deletion.

An observation retains both the newest authenticated manifest revision and the
last complete checkpoint (revision, deletion status and SHA-256 digest). A newer
manifest remains observed even when ciphertext cannot be read or cancellation
wins immediately after authentication. Chunk assembly uses that exact manifest;
it never rereads mutable metadata to select another snapshot.

`ObserveVPNSSO` imports and returns these monotonic floors for the trusted native
device anchor. An authenticated external minimum is retained before database I/O
and survives a failed read or a later request omitting it. Observation metadata
remains available after a policy denial, without releasing archive bytes or
weakening policy. A cancelled operation needs a separate cleanup context to
collect its observations before shutdown.

Before using borrowed bytes, the native callback must independently anchor its
complete snapshot checkpoint, with the same manifest revision. Callbacks must
not reenter the owner. After every operation, including failure, its native
controller must collect and anchor the latest observation before exposing the
final session or reporting denial. The owner retains floors across failed
delivery and attempt close, until shutdown. The registry is bounded to 1,024
scopes and never evicts an older floor to admit a new one.

Imported observations detect both complete database replay and partial manifest
rollback after a restart. The native controller persists/imports these observations
in the authenticated signed slot file, so replaying an older database against a
newer slot is refused. A separate protected device anchor is still required to
detect replay of both the complete database and its older signed slot. That whole
local-state replay remains the documented limitation.

Default and Standard are the supported durable profiles. Policy and OS floors
are checked on each open, save and deletion; unsupported stricter profiles fail
closed through the existing security gate. Owner shutdown retires all attempt
and observation metadata and closes its protected root. Implementing in-memory
SSO at Hardened/Paranoid remains part of their broader release gates.

## Verification scope

Go regressions exercise encrypted multi-chunk round trips and reopen, actual
maximum-size storage and chunk shrinking, all binding dimensions, malformed
records, account substitution, concurrent captures, delete/recreate, lost writes,
cancelled reads and acknowledgements, expiry, policy changes, registry capacity,
buffer wiping and a real whole-database replay across owner restarts. These prove
the custody primitive. They also cover withheld ciphertext, manifest observation
before cancellation, partial-floor export/import across actual owner restarts,
and observation access after a policy denial. They do not prove native provider
storage capture/restore or interoperability with a real VPN provider.
