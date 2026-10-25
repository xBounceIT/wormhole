# Forcepoint SSL VPN

Forcepoint tunnels use a native Go implementation of SSVTP version 9 over TLS.
The Forcepoint client, its Windows service and its drivers are not dependencies.
IPsec, MFA, client certificates and endpoint security checks are outside this
provider's supported authentication flow.

Create a **Forcepoint** tunnel with a gateway host, SSL port (443 by default),
username and password. The advanced settings expose an optional server certificate
SHA-256 pin and MTU (1390 by default). With no saved pin, Go checks the gateway's
public TLS certificate before starting VPN authentication. A private CA or hostname
mismatch opens the existing VPN confirmation dialog with the subject, issuer,
expiry and SHA-256 fingerprint. Compare that fingerprint with the administrator
or an already trusted Forcepoint client before accepting. Consent saves the exact
leaf certificate pin in the protected tunnel settings. Rejection or cancellation
sends no VPN credentials. Profile updates, deletion and trust persistence share a
cross-process storage lock, so stale consent cannot overwrite newer settings.
First-connection discovery rejects expired certificates.

System CA and hostname verification apply to normally trusted certificates. A saved
pin is enforced by the native transport and is never replaced automatically when
the peer certificate changes. There is no option to disable all certificate checks.
The original client's Certificates tab lists imported user certificates; gateway
fingerprint verification is a separate step, also when using username/password.

The shared tunnel editor supports creation and editing; the resulting tunnel can
be selected by Quick Connect and saved connections using the normal tunnel route.
Credentials use the backend's protected tunnel settings store and reach the
transport through stdin. Authentication responses, configuration XML and tunnel
packets are never logged or written to diagnostic files.

## Transport and isolation

The native implementation shares the existing SSL sidecar process and SOCKS5
surface with AnyConnect. Its private stdin discriminator is
`"vpn_protocol": "forcepoint-ssl"`; an omitted discriminator retains AnyConnect.
Existing release scripts therefore compile and package both transports together.

Each Forcepoint session owns its own TLS connection, private virtual network stack
and locally administered DHCP identity. Reauthentication and unchanged configuration
updates retain that identity; independent tunnel sessions get different identities.
IPv4 addresses, DNS servers and protected subnets come from the gateway. The routes
exist only inside the Go stack, including full-tunnel routes. Host adapters, routes
and DNS settings remain unchanged. DNS resolution uses only the VPN's DNS servers.

Keepalives detect a lost peer. Authentication rejection, expired authentication,
unsupported security requirements, malformed messages, or a changed network
configuration close the transport and the parent tunnel lease. Data is suspended
during server-requested reauthentication. Changed addresses/routes/DNS require
reconnection so existing connections cannot retain stale network state. An IPv6-only
configuration fails closed; IPv6 transport packets are not supported.

## Verification

Go tests cover the wire framing and bounds, TLS trust, username/password challenges,
reauthentication, configuration parsing, private routes, per-session DHCP identity,
dead-peer teardown, and a TCP echo exchange between two userspace network stacks.
Backend tests cover protected persistence, sanitized summaries, validation and the
supervised process lifecycle, plus TLS discovery without application data,
certificate consent/rejection, expiry, cancellation and concurrent edits.
Renderer tests cover normalization, field validation, IPC bounds and the mounted
editor sections. Chromium layout tests measure the paired gateway and certificate
controls at desktop and compact widths, including the advanced section toggle.

React TSX and process entrypoints are excluded from the project's loaded-module
coverage percentage, as documented in `scripts/test-coverage.ts`; scoped integration
and source-contract tests cover that glue.

The unauthenticated SSVTP version negotiation was checked against a Forcepoint
gateway. A real username/password login, access to an internal destination and a
gateway-disconnection test must also be performed in the user's environment before
claiming production interoperability. The Windows client installation and successful
automated tests alone do not establish that result.
