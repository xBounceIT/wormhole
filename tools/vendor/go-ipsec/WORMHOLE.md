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
local extensions and the integration are tested explicitly. IKEv1, Fortinet TCP
encapsulation, SAML over a shared IKE TCP port, and EAP-TTLS are not implemented.
Real FortiGate/IdP interoperability still requires an integration environment.
