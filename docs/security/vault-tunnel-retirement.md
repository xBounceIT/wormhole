# Native VPN process retirement

The isolated Go route controller owns its original VPN sidecar until the sidecar's
OS wait completes. A pipe closing, a successful kill request or an elapsed close
timeout does not acknowledge that exit. A failed wait without an OS process state
leaves retirement unconfirmed. This applies after readiness, cancellation, invalid
control input, lost output and startup failure.

After a sidecar starts, the launcher returns its owned process even alongside an
error. The controller wipes the borrowed configuration before joining retirement;
the provider launcher also wipes its temporary sidecar configuration on return.
This keeps a slow or uncertain shutdown from retaining those secret buffers. A
failed startup cannot discard the process identity and then declare cleanup done.

Main closes the controller's input and allows eight seconds for the normal native
graceful/forced sidecar cleanup and OS wait. Main never force-kills this controller
to manufacture an exit receipt. If the controller has not exited, cleanup rejects
and the broker retains its original reservation. Retrying joins the same owner.
The generic process-stop helper retains its previous forced-stop behavior for
callers that do not opt out.

While retirement is unconfirmed, another session cannot replace the same
workspace/file/tunnel merely by changing its configuration revision, provider or
authorization epoch. Independent tunnels keep independent ownership. The original
entry is removed only after the original controller and any native authentication
document have confirmed cleanup.

Tests cover unconfirmed cleanup, original-process identity, startup failure,
configuration wiping, a failed wait without process state, changed configuration
and provider attempts, and independence of other tunnels. A real Go controller
and a real synthetic sidecar also exercise a 2.4-second shutdown through the
production Electron broker and HPKE handoff. No real VPN gateway is needed for
these process-lifecycle checks.

The [IPsec-to-SSL fallback broker](vault-tunnel-fallback.md) now uses this barrier
before selecting and independently authorizing its second source. Each consumer
must obtain its own fresh target Use, and secondary authentication carries the
complete source pair. Real primary/secondary recipients and slow synthetic
sidecars verify this ordering; real provider authentication remains unverified.
A saved fallback reference grants no such authority.
