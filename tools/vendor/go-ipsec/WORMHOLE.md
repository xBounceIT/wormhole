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

The IKEv2 path supports PSK or RSA/ECDSA client certificates, with user
authentication disabled, prompted/saved EAP credentials, or SAML. SAML is an
explicit user-authentication choice, not a requirement. Fortinet certificate/EAP
sends the certificate chain for the gateway's pre-EAP certificate check, verifies
the responder's trusted certificate and AUTH before sending user credentials,
then uses Fortinet's SK_pi/SK_pr final AUTH. This is the Fortinet EAP extension,
not a claim of RFC 4739 multiple-auth interoperability with arbitrary gateways.
The gateway must enable its corresponding certificate/EAP policy.

Explicit IKEv2 proposals support the full editor matrix: AES-128/192/256 or
3DES with MD5/SHA-1/SHA-256/384/512, independently for IKE and ESP. The negotiated
PRF drives AUTH, key expansion and rekeys; an IKE rekey uses the old PRF for
SKEYSEED and the new PRF for its key expansion. DH groups 1/2/5/14-21 and the
selected Child PFS group are honored. A Fortinet profile cannot silently remove
required PFS or change its group during a server-initiated rekey. Existing SAML
profiles retain automatic proposals when opened and saved.

Addressing supports Mode Config, a manual IPv4 address/DNS, and DHCP packets
carried inside authenticated ESP. DHCP validates the transaction/client/server,
packet bounds/checksums and lease options, renews at T1, rebinds at T2, and fails
closed on NAK or expiry. On FortiGate, IKEv1 DHCP relay uses DHCP over IPsec;
IKEv2 DHCP proxy assigns its DHCP address through Mode Config, so choose Mode
Config for that gateway configuration:
https://community.fortinet.com/fortigate-3/technical-tip-how-to-configure-ipsec-dialup-vpn-using-ikev2-with-dhcp-proxy-and-giaddr-93875

Disabling NAT-T uses a separate raw IP protocol 50 socket for ESP and plain UDP
for IKE, without NAT notifies, port floating, or NAT keepalives. Creating that
socket requires an elevated Windows token, root, or CAP_NET_RAW, and the path
must permit ESP. Permission failures never re-enable UDP encapsulation. Raw ESP
cannot use a custom outer PacketDialer. The native socket adapter is portable;
its read, write, source filtering, errors and cancellation are unit tested.

Local LAN is an explicit bypass for currently connected interface prefixes;
prefixes are refreshed on every dial. DNS still resolves inside ESP. Errors do
not enable bypass, and closing the VPN closes its tracked LAN sockets too.
Replay detection and time/byte lifetimes are independently configurable. Hard
limits prevent further encryption/decryption, even while renewal is pending.
DHCP readdressing updates only the layer-3 configuration, preserving a concurrent
SA rekey. Additional gateways are tried in order; SAML tokens stay bound to their
issuer.

SSL fallback references an existing Fortinet SSL profile in the protected
backend. Failed IPsec startup may start that profile's own authentication flow;
user cancellation aborts both attempts. The shared lease identity includes the
fallback configuration fingerprint, and the fingerprint is rechecked before
starting SSL. Existing application streams fail closed when a live tunnel dies;
fallback is performed during tunnel establishment, not by rerouting live streams.

Validation uses Go's statement coverage and Node's native loaded-module
coverage. Unchanged imported third-party source is excluded from changed-code
coverage. React TSX layout and the Electron process entrypoint follow the
project's source-contract/native-fixture coverage convention rather than being
counted as directly loaded Node unit modules. OS allocation failures and
`crypto/rand` failures are not fault-injected. No live FortiGate, external IdP
or real provider certificate is needed by the offline suites.

Validation after adversarial review: 84.49% of changed Go statements (1100/1302),
using Go coverage blocks and the threshold/parser in scripts/test-coverage.ts.
Cross-package profiles are merged by source block before counting. The shared
Fortinet state helper has 100% line/function and 97.73% branch coverage.
The full backend suite, IPSec suite with the race detector, sidecar tests,
142 UI/authentication contract tests and the real sandboxed credential-window
fixture pass. Sidecar compilation passes on Windows amd64/arm64, Linux amd64
and Darwin arm64. Live gateway/IdP behavior and privileged raw ESP on each
operating system remain integration checks; compilation is not interoperability.

The completed adversarial finding ledger, clean-cycle evidence and final
verification are recorded in `REVIEW.md`.
