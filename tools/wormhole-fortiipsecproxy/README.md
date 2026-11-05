# Fortinet IPsec / SAML

Userspace IKEv2 + ESP/NAT-T sidecar, independent of the existing Fortinet SSL/PPP
provider. No administrator privileges, kernel VPN, FortiClient installation or
system route changes are required. Application traffic and DNS use the tunnel;
there is no direct fallback.

The Go backend initializes the FortiGate `auth-ike-saml-port` endpoint (default
HTTPS 1001), reserves a fresh loopback callback port, and opens the native isolated
SAML window. Electron intercepts the exact callback and returns only its temporary
token to Go. The UID binds that token to the subsequent EAP-MSCHAPv2 or EAP-GTC exchange. The
gateway must prove possession of the configured PSK before receiving the token.

Configuration is a bounded JSON line on stdin. The backend protects the PSK in its
existing secret store; temporary UID/token values cannot be saved in tunnel settings.
`READY <port>` is emitted only after IKE authentication and userspace network setup.
EOF, cancellation and dead-peer detection release the tunnel and SOCKS clients.

In **VPN tunnels**, choose **Fortinet IPsec (SAML)** and provide gateway, IKE UDP
port (default 500), SAML HTTPS port and gateway PSK. Set local/remote IKE identities
when required by the gateway. The SAML endpoint must support the UID/REDIRECT_PORT
browser callback flow. Gateway HTTPS certificates are verified by default; the
explicit trust switch applies only to the SAML HTTPS flow, while IKE still verifies
the PSK. UDP NAT-T port 4500 must be reachable.

Supported proposals: AES-256-GCM, AES-256-CBC/SHA-256, ChaCha20-Poly1305; SHA-256
PRF; DH groups 14, 19, 20, 31. Supported authentication: PSK-authenticated gateway
with SAML-token EAP-MSCHAPv2 or EAP-GTC client. IKEv1, certificate-authenticated IKE gateways,
EAP-TTLS and Fortinet IPsec-over-TCP are outside this provider's current support.
The Fortinet PSK/EAP profile uses session-key AUTH (SK_pi/SK_pr), while still
verifying the current MSCHAPv2 server proof. Additional EAP factor continuations
are rejected before final AUTH; post-login OTP/push prompting is not implemented.

The IKE engine is pinned and vendored with its MIT license and upstream tests.
Go 1.26.10 or newer is required for the fixed certificate and ASN.1 implementations.
See [local engine changes](../vendor/go-ipsec/WORMHOLE.md). Run `npm run
test:fortiipsecproxy`, `npm run test:ipsec-engine`, and the backend FortinetIPsec
tests. Coverage is measured using Go cover profiles and Node's native V8 tooling.
The executable entrypoint/signal wiring is excluded from behavioral unit coverage;
the injectable process runner and native callback handlers are exercised directly.

Automated tests cover SAML initialization, TLS failures, callback isolation,
protected persistence, native process leases, offline IKE/EAP-GTC success and
failure paths, ESP loopback, DNS confinement and EOF/peer shutdown. Real FortiGate
firmware and IdP interoperability requires a live integration test; it is not
established by the scripted responder.
