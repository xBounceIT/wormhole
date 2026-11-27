# Fortinet SSL browser authentication in the vault

Fortinet SSL SSO now uses the sealed native route process for both local and
shared saved connections. Go validates the authenticated kind-2 configuration,
constructs the gateway/realm URL and creates a fresh locked HPKE recipient.
The original session owner opens a sandboxed native browser with no preload or
application IPC. Its volatile profile is independent of the native challenge ID.

In cookie mode, main accepts a fresh `SVPNCOOKIE` which Chromium commits after an HttpOnly
Set-Cookie response from the exact expected gateway and WebContents. A native
cookie event must match that response's digest, gateway domain and request path.
Old, JavaScript-accessible, foreign, removed, expired and replaced values cannot
complete the flow. Cookie capture uses commit events rather than a polling or
asynchronous cookie read that could finish after teardown. The opaque cookie is
consumed before asynchronous encryption and never crosses ordinary renderer IPC.

With `UseSamlCallback`, Go requests `/remote/saml/start?redirect=1`. The isolated
window captures the authentication ID from the gateway's main-frame
`/remote/saml/login` response or a navigation initiated by that page. Chromium
cancels the loopback request before it reaches a local listener. Go accepts one
visible-ASCII authentication ID of up to 4096 bytes.

The authenticated encryption context covers the route identities and revisions,
challenge, start URL, TLS policy and completion mode. Go validates the encrypted
frame and the credential format for that mode. A successful native completion
produces a private launch witness for exactly that binding and configuration.
Stored SVPN cookies or SAML authentication IDs cannot mint this witness. Stale
password, username, TOTP and browser/callback fields are discarded for this
launch, without rewriting the saved profile. Configuration reaches the native
sidecar through stdin, with provider diagnostics discarded.

All four route brokers retain original-owner, epoch and pooled-lease rules.
Cancellation, lock, EOF and replay retire the native attempt. Main confirms
window destruction, pending encryption and profile/connection/cache/auth cleanup
before acknowledging completion. A failed cleanup quarantines new browser
admission until an explicit retry succeeds. Permissions, downloads, file access
and untrusted popups remain blocked; gateway certificate exceptions do not widen
to other origins. The existing SSO-plus-certificate-pin restriction is preserved.

The native session restores supported provider state before navigation and
captures it into the encrypted personal archive before returning a fresh login
result. Local and shared sources use their own authenticated admission; shared
sources use personal/device custody, with migration 42 for enrolled key proofs.
The volatile Chromium profile is cleared after confirmed window destruction.
Worker and cache state, nonextractable keys and the remaining security profiles
are still open. For a configured fallback, the broker confirms that the IPsec
process has stopped and obtains independent authorization for the SSL route.
[IPsec-to-SSL fallback](vault-tunnel-fallback.md)

Tests cover purpose/context substitution, malformed values, the full 16 KiB
cookie frame, stale/header-free/non-HttpOnly values, gateway/domain/path checks,
deletion/replacement, owner cancellation, replay and launch-witness substitution.
Real Chromium tests use a synthetic HTTPS gateway and the production Go recipient
for immediate, redirected, delayed and large cookies, cancellation, missing
HttpOnly and expiry. They also exercise an HTTP redirect and a page-initiated
navigation carrying a callback ID. A loopback listener records zero requests in
both cases and when the gateway sends a callback from an unauthorized path.
Live FortiGate interoperability remains unverified.
