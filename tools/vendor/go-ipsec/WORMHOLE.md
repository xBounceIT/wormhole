# Wormhole Fortinet adapter

Vendored from MIT-licensed `github.com/n0madic/go-ipsec`, commit
`96f638aa680f` (2026-10-03). The upstream license and automated tests are retained.
This is a source dependency, not a second executable or system VPN service.
The Go minimum is raised to 1.26.10 for GO-2026-6809 and GO-2026-5972.

Local extensions are explicitly opt-in: Fortinet SAML EAP-MSCHAPv2/EAP-GTC, independent
responder PSK authentication, owner notification on peer death, and RFC 5903
P-256/P-384 DH groups (19/20). Standard PSK and certificate/MSCHAPv2 paths remain
covered by the upstream offline handshake and crypto tests.
All supported DH groups are advertised in initial and retry IKE_SA_INIT proposals;
offline responders reject selection of a group absent from the client's offer.
Initial Child SA proposals omit DH transforms as required by RFC 7296 section 1.2,
across Fortinet SAML, PSK and certificate/EAP authentication. IKE_AUTH responses
with a separate KE or non-NONE DH selection are rejected. CREATE_CHILD_SA retains
its separate PFS negotiation and key derivation.

The explicit Fortinet PSK/EAP path uses SK_pi/SK_pr for post-EAP AUTH even after
MSCHAPv2, while still verifying its current server proof. EAP notifications are
acknowledged without credentials. Extended Success that requests another factor
fails closed; additional OTP/push prompting is outside this SAML provider.

Fortinet protocol references:

- https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/951346/saml-based-authentication-for-forticlient-remote-access-dialup-ipsec-vpn-clients
- https://github.com/quincampoix/fortigate-saml-vpn/blob/main/docs/protocol.md
- RFC 3748 section 5.6; RFC 7296 section 2.16; RFC 5903.
- https://raw.githubusercontent.com/Noneawe/strongswan-deb-build/main/patches/eap_authenticator-fortigate-pskauth.patch

Run `go test ./... -coverprofile=coverage.out` here as well as the sidecar and
backend suites. Third-party unchanged code is excluded from changed-code coverage;
local extensions and the integration are tested explicitly. Fortinet TCP
encapsulation, SAML over a shared IKE TCP port, and EAP-TTLS are not implemented.
Real FortiGate/IdP interoperability still requires an integration environment.

## Configurable Fortinet authentication and IKEv1

The IKEv1 exchange implementation under `internal/ikev1` and the small shared
DH/PRF primitives under `internal/legacycrypto` originate from MIT-licensed
`github.com/xen0bit/veepin`, commit `bcac1789f0a7eaa7687b2777d6d6765fb87158e0`.
`LICENSE-ikev1` preserves its license. Upstream exchange tests are retained;
the original logging adapter is replaced by a silent adapter so protocol
messages, usernames, banners and credentials cannot reach diagnostics.

Local additions include explicit IKE/ESP proposals, AES-128/192/256 and 3DES,
MD5/SHA-1/SHA-256/384/512, RFC 2409/3526 MODP groups and RFC 5903 ECP groups,
RSA certificate authentication, XAuth with PSK or RSA, manual addressing,
replay policy, Quick Mode PFS, authenticated cookie/message-id checks, and
Child SA renewal. The adapter exposes the same isolated userspace network as
IKEv2, keeps DNS inside ESP, and closes on failure or IKE SA expiry. Phase 1
reauthentication currently requires reconnecting; it never reuses expired keys.

The IKEv2 path additionally supports client certificates (RSA or ECDSA) and
ordinary PSK/EAP passwords without a SAML browser. Existing SAML profiles keep
automatic proposals when opened and saved. Explicit IKEv2 proposals currently
require AES-256/SHA-256; configurable DH groups are 14/19/20 and Child PFS is
group 14. IKEv1 permits the legacy proposals shown in the editor.

Remaining capability limits are explicit connection errors: DHCP over IPsec,
disabled NAT-T/raw ESP, local-LAN bypass, IKEv2 certificate-plus-EAP, and IKEv2
volume lifetimes or disabled replay/time lifetimes. SSL-VPN failover is not
implemented. Additional gateways are tried in order, with independent startup
attempts; SAML credentials remain bound to the gateway that issued them.

Validation uses Go's statement coverage and Node's native loaded-module
coverage. Unchanged imported third-party source is excluded from changed-code
coverage. React TSX layout and the Electron process entrypoint follow the
project's source-contract/native-fixture coverage convention rather than being
counted as directly loaded Node unit modules. OS allocation failures and
`crypto/rand` failures are not fault-injected. No live FortiGate, external IdP
or real provider certificate is needed by the offline suites.
