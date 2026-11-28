# Native VPN SSO admission and checkpoint transport

Issue [#495](https://github.com/xBounceIT/wormhole/issues/495) remains incomplete.
This connects personal encrypted SSO custody to the Go stdio service and a
main-process Electron capability. Local SSL and IPsec SAML browsers now use the
[owning native session](vault-vpn-browser.md) to restore/capture actual supported
storage. Shared SSL/IPsec browsers now use personal/device custody with the
source workspace retaining authorization. Shared deployment migration 42 is
required for enrolled author proofs and final recipient selection. Broader
profile and roadmap work remains.

## Source admission

`PlanConnectionVPNSSO` resolves the original connection request inside the local
owner. The credential override, target, session, request, epoch and authenticated
tunnel binding remain exact. A metadata-only tunnel row advance is allowed;
changing configuration or another binding member requires a new attempt.
Admission supports local Fortinet SSL and IPsec SAML provider adapters. SSL
checks the selected SAML start URL, realm and certificate policy against the
borrowed authenticated tunnel configuration. IPsec checks SAML mode, exact path,
configured SAML port, selected primary/additional gateway and TLS policy. Its fresh
query is completion-bound and excluded from stable retained-scope selection.
Account scope identifies the local
Wormhole owner; the route digest includes the supported upstream VPN hop.

Begin independently resolves again under the owner lock. Every subsequent
restore, acknowledgement, capture and commit rechecks the source and personal
effective profile. Authenticated source-node observations are retained even when
resolution subsequently refuses deletion, ancestry or account selection. Quick
targets keep their native temporary admission and do not become persisted nodes.
Shared native operations and the app browser factory use a separate personal/
device owner with the source-policy adapter described below.

## Shared personal custody

Ordinary shared unlock adopts the enrollment's random device storage root into
the same admission gate as protocol keys, then closes account derivation roots.
Remote revocation and native close retire both protocol and personal state keys.
The personal SQLite file holds encrypted SSO state; it is never exposed as a
second application workspace or tree. A missing previously observed cache is a
rollback failure. Default/Standard remain the supported runtime profiles.

Each archive action obtains a fresh audited Source Use and verifies the source
graph, original route, provider settings, selected origin/TLS policy and account.
A synchronous native receipt supplies that source's effective security policy
to the personal owner. It expires when the admitted callback returns. Ongoing
transfer checks compare fresh receipts without recursively acquiring admission.
Cancellation can release the original reservation after source revocation.

Native transfer context identifies personal custody; its binding digest still
identifies the shared source. Main captures the personal vault ID from the
authenticated native workspace selection and passes a strict optional `custody`
object. The native root checks it against device enrollment, and the DTO reader
checks the offer against that captured selection.

Checkpoint publication advances the original enrollment slot/envelope pair and
then its OS-protected startup sequence floor before releasing any response. It
does not create a duplicate password capsule. Password rewraps retain the random
storage root and all SSO/profile/source floors. Missing anchors, changed native
files or unconfirmed writes fail closed and retire shared admission.

Migration **42** publishes public enrollment chains alongside the current signed
bootstrap account state. Graph format **5** selects the final user encryption key
from that verified chain; connection snapshot format **3** and author/copy rows
include the final signing proof. Native verification matches the source chain to
the independently established enrollment pin before opening private material.
It keeps direct organisation certificates and delegated proofs exclusive.

Protected trust format **6** keeps final manifest floors separate from bootstrap
certificate floors. Final selection pins bind both bootstrap references, so a
signed reset of either can select a fresh pair without weakening the previous
anchor. A conflicting pair under the same bootstrap is refused before reserving
new key or record floors. Valid newer bootstrap certificates remain observations
when a delegation, record or account capsule fails. A failed capsule cannot
advance its claimed wrapping revision. Ordinary unlock and password recovery
persist these public observations before returning the failure.

Tests exercise real PostgreSQL migration atomicity/ACLs, enrolled author reads,
audited credential/settings release and opening with final keys. Separate native
end-to-end tests use real Go roots, disposable recipients and Chromium in local
and shared SSL/IPsec modes; their shared transport is a cryptographically verified
fixture. They do not establish interoperability with a real identity provider or
VPN gateway, or a complete live application enrollment-to-browser deployment.

## Authenticated device observations

Slot **container v2** adds sorted `vpnSso` and `tunnels` high-water marks to the
existing authenticated document. Cryptographic secret-envelope format stays v1.
Readers continue to accept container v1; writers cannot downgrade v2 or remove
or lower authenticated observations. The public descriptor exposes only version
and existing slot hints. It never exposes these marks or key material.

The owner imports complete and partial SSO observations before use. The native
writer merges source-node, tunnel, profile and SSO floors with the current slot
file and commits atomically. No-op observations avoid rewriting the file. A
failed write does not advance the owner's slot sequence. A missing slot file is
an error and cannot be silently recreated by a transfer.

Every stdio operation imports checkpoints before acting and persists all new
observations before publishing its response, including on denial. Cleanup uses a
separate bounded context after cancellation. A final owner gate refuses a
prepared response if checkpoint import discovered a newer source observation.
An uncertain checkpoint write retires the vault owner.

These authenticated marks detect a database replay against retained native slot
state. Replaying the database and the entire corresponding slot file together
retains the documented local whole-file rollback limitation; this is not an
external monotonic hardware anchor.

## Native transport and lifetime

The main-only operations are `vpn-sso-begin`, `vpn-sso-take`,
`vpn-sso-restore-ack`, `vpn-sso-push`, `vpn-sso-commit` and `vpn-sso-cancel`.
They validate exact bounded schemas and carry public metadata or sealed chunks.
They do not return browser storage, completion credentials or private keys.
Restore packets retain the existing 8 MiB response allowance for an exact 4 MiB
encrypted archive chunk; unrelated metadata retains its smaller limit.

The Electron host captures one exact backend process and authority predicate.
Detached contexts prevent mutation by the caller or backend response object.
Late begins and replies cancel on that original process, including after host
replacement. Capture cannot overlap another operation. A successful commit
consumes the capability. Cleanup can be retried; absence after commit, expiry or
failure confirms release only within the matching native owner. A live stage
still requires its complete original context, and old cleanup cannot retire a
new stage using the same browser profile ID.

There is no preload or renderer IPC endpoint for this transport. Route prompts
now receive a frozen copy of their original request, including the credential
override, for the future native browser controller.

## Verification and remaining integration

Regression coverage includes actual Go stdio-handler custody round trips,
publication ordering, missing-file retirement, malformed messages, native writer
rollback guards, restart with partial floors, denied-source deletion, Quick
target isolation, repeated cleanup and the final response gate. Electron tests
exercise all six production client methods, large chunk framing, detached
contexts, late responses, concurrency and original-owner cancellation.

The [disposable Go recipient and origin serializer](vault-vpn-browser.md) have
real subprocess and Chromium regression coverage and are connected to both local
SSL and IPsec actors through the owning session driver. It joins restore/capture,
requires root acknowledgement before network/presentation and preserves separate
fresh completion proof. Unsupported storage, encrypted migration inventories,
complete live shared deployment validation and remaining policy/roadmap work
are still required.
Hardened and Paranoid remain unavailable.
