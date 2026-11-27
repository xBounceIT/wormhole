# IPsec-to-SSL fallback context

The main-only route broker now connects native IPsec startup failure to a fresh,
independently authorized SSL attempt across web, SSH/SFTP, RDP and VNC. A saved
reference or an encrypted packet grants no Use authority and does not prove that
the original process has exited. Real provider interoperability remains unverified.

`vault.TunnelFallbackBinding` now binds both the exact original IPsec route
(kind9) and the secondary SSL route (kind2). Both routes must share workspace,
native file identity, node, session, protocol, destination host/port and unlock
epoch. They must select different tunnel IDs and different request IDs. Each
source carries its independent authenticated row/configuration revisions.
Revisions retain their decimal-string wire encoding.

`SealTunnelFallback` and `OpenTunnelFallback` use the existing bounded HPKE
envelope with a separate `wormhole/v1/tunnel-fallback` purpose. The canonical
context includes both complete route bindings. Ordinary tunnel or credential
packets cannot be substituted for this purpose, nor can either source, revision,
destination or attempt be retagged. The native recipient must still be consumed
once; the stateless cryptographic primitive does not maintain a replay registry.

The local Go owner now authenticates the connection, primary manifest and encrypted
primary-to-fallback reference under one lock. Planning opens only the primary
settings. Sealing re-resolves both sources and checks the exact expected pair
before opening the secondary settings. A different provider, deleted target,
changed source, stale revision or substituted destination cannot release the
secondary configuration. Borrowed primary settings are wiped before the target
is read.

The native stdio operations `tunnel-fallback-plan` and
`tunnel-fallback-bundle` accept a connection context and source snapshot. The
plan derives its target from the encrypted primary settings. A caller's claimed
source pair grants no authority, and settings are never accepted as caller input.
The Go provider adapter validates the IPsec settings and extracts their configured reference. Responses
contain only bound metadata or purpose-bound ciphertext for a fresh recipient.
In local mode, authenticated node, tunnel and policy observations reach the protected slot
checkpoint before a response is published, including observations made on denial.
Late cancellation suppresses the response. A known policy failure takes
precedence over concurrent cancellation and retires the owner after checkpointing.

These operations now also serve shared sessions through their independently
audited source API. Main-only Electron codecs, client and host methods now expose
the typed plan and sealed packet. They strictly validate both complete bindings,
the unchanged original source, independent request/tunnel IDs and source versions,
and the common workspace/file/connection/session/destination/epoch. The bundle
response must match the exact planned pair. Requests are detached snapshots;
workspace and caller authority are checked before and after native work. Unknown
fields are refused before deriving nested context. Maximum sealed frames use the
bounded ciphertext channel. No renderer IPC or Electron broker calls expose or
activate this flow yet.

PostgreSQL migration 43 adds `begin_fallback_use` and `fetch_fallback_secret`.
The secondary intent has its own committed audit entry identifying both tunnels.
Issuance and consumption enforce current connection permissions and independent
secondary boundary Use. Ordinary and fallback tickets share the bounded device
slot and irreversible counter, but cannot consume one another. Replacement resets
the purpose and both source IDs explicitly. Rollback or savepoint rollback cannot
restore a consumed ticket.

The new Go transport strictly decodes a separate target manifest, encrypted
settings and key copies alongside the unchanged format5 source graph. It keeps
final enrollment recipients and public author proofs. This decoded object is
unverified ciphertext, with no public key-opening method. `VerifyFallbackRelease`
now authenticates both graphs and returns their combined observations without
opening keys. It rechecks both chains against all newly learned floors before
preparing use: a final author pin learned from the target cannot leave an earlier
bootstrap source usable. Signed tombstones and provider changes are authenticated
before policy refusal, so their observations can survive denial.

The shared controller commits those observations to the protected trust file and
startup anchor before any account-key loan. It discovers the target through a
fresh audited primary opening, then obtains a separate secondary audit and graph.
Reference validation opens only primary settings and consumes the prepared
graph's existing one-use gate. Sealing obtains a fresh graph, validates the exact
source pair and encrypted reference, ends the primary loan, then opens only the
target settings. Failure, cancellation and callback panic wipe borrowed buffers.
The signed original connection plan continues to select IPsec throughout.

The native `tunnel-fallback-sealed` mode now owns an independent recipient and
accepts only the fallback packet purpose. It authenticates the complete pair,
then uses the active SSL binding for startup and fresh cookie challenges. It
reuses the ordinary actor's single packet lifetime, bounded controls, secret
wiping, cancellation and OS-confirmed sidecar retirement. Ordinary and fallback
recipients refuse each other's packets, including a retagged wrapper.

The explicit `tunnel-primary-sealed` actor validates the original IPsec settings
and encrypted reference, then removes only the fallback control field from a
native copy before invoking the existing adapters. Ordinary launch/authentication
guards remain enabled. Operational startup failure may emit a bounded
`fallback-required` event only before readiness. Provider discovery can fail
before creating a process; any owned sidecar must first finish its actual OS wait.
Invalid settings or controls, cancelled or declined authentication, a successful
primary and a later established-route failure never authorize another attempt.

Main validates the original session/request, joins original controller retirement
and authentication cleanup, then obtains a fresh fallback plan and creates the
separate recipient. It never force-kills the original controller to claim exit.
An uncertain shutdown quarantines both source identities until explicit cleanup
succeeds. A secondary failure cannot recurse or select a direct route.

Pool identity includes both source IDs and configuration versions. Each pending
or newly joining consumer obtains its own independent native target authorization
before receiving the endpoint. Its lease retains its own logical primary route
for credential release; the active SSL binding and full pair govern secondary
authentication and retained SSO. Cancellation joins transition work, and late
events from the original controller cannot affect its replacement.

Retained SSL SSO now has an explicit pair-aware admission path. The original
connection request continues to identify IPsec; the active cookie challenge uses
the separate SSL request ID. Local admission and every archive action reopen the
encrypted primary reference and exact target under one owner lock. Shared actions
obtain a new independently audited fallback graph, authenticate both sources,
publish protected observations, then borrow only the required settings. The
ordinary selected-source comparison remains unchanged. Personal archive custody
and the cache identity include both source IDs/configuration versions, account,
provider origin/realm and TLS trust, without including ephemeral attempts.

Local commit retains a native source revalidator after retiring the transfer.
It rechecks after checkpoint publication, including a second publication that
imports a newer authentic floor. Newly discovered facts suppress the receipt and
are checkpointed before denial; there is no automatic admission retry. The
browser dialog/session snapshots and forwards the explicit pair through the
main-only SSO transport. The complete pair has a 16 KiB request limit; ordinary
single-source SSO retains its 8 KiB limit. All four production brokers pass this
pair through their matching native browser dialog.

Tests exercise both directions of purpose substitution, malformed envelopes,
invalid or mismatched sources, retagging of common fields, independent attempt
IDs, exact source revisions, the full4MiB configuration limit and authenticated
empty-payload refusal. Real local SQLite owner and stdio tests also cover encrypted
reference resolution, target/source edits, MAC and ciphertext corruption,
rollback, deletion, malformed requests, checkpoint failure
and cancellation. They do not prove a working provider fallback or live
provider interoperability. Localhost PostgreSQL tests additionally exercise
migration identity/rollback/ACLs, both account key states, committed audit,
independent Use, purpose isolation, replacement, missing ciphertext and
rollback-resistant consumption, native proof verification and target opening for
bootstrap and final recipients. Native controller tests exercise real protected
trust/anchor publication, independent observations on rejection, purpose-bound
HPKE handoff and anchor failure suppression. They do not establish a working
live provider interoperability.

Main codec tests cover missing/unknown fields, both source replacements, provider
and destination changes, decimal revision limits, replayed request IDs, packet
bounds and authority loss. Client transport tests use the real bounded frame
parser. Local Electron-to-Go interoperability additionally resolves an encrypted
IPsec reference, receives the exact pair, opens the separate HPKE purpose and
rejects ordinary-purpose substitution. An altered target revision retires the
native owner and requires an explicit new unlock. This test calls the source API;
it does not start a secondary VPN or establish an original-process exit receipt.

Secondary actor tests exercise ready/error, EOF, lock, replay, wrong session,
source retagging, ordinary-purpose substitution and cookie cancellation/replay.
A synthetic local sidecar receives its configuration through stdin and delays
exit; successful and failed startup cannot acknowledge cleanup until Cmd.Wait
confirms its real OS process state. These lifecycle tests require no VPN server
and do not demonstrate live provider authentication. The production broker also
drives real primary and secondary Go recipients with real HPKE and slow synthetic
sidecars: target authorization and secondary creation occur only after the
original controller has exited. The test retains the logical primary lease,
checks distinct recipient keys and joins secondary cleanup without a main kill.

SSO tests change each source before begin/take/ack/push/commit/final receipt and
verify the original request vs active SSL challenge, private-key loan ordering,
cache separation and publication. A valid newer protected target floor injected
during commit publication reproduced a stale successful receipt before the fix;
the response is now suppressed. Real Chromium/Go tests restore and recapture
cookies, local/session storage and IndexedDB for ordinary SSL/IPsec and both
local/shared fallback sources, and join original-owner shutdown. Shared tests
use genuine enrolled proofs with a fixture query/audit transport; these are not
a live application-to-PostgreSQL or real provider login demonstration.
