# Workspace CA and server CSR issuance

The native `internal/sharedpg` implementation can create a workspace server CA,
wrap its private scalar to the organisation encryption key, and issue a server
certificate from a server-generated CSR. Self-hosted provisioning uses this CA
and publishes a [signed TLS trust bundle](vault-tls-trust-bundle.md) with approved
hosts and a protected sequence floor.

An enrolled administrator at Default or Standard can renew the PostgreSQL
server certificate from the shared workspace. Open **PostgreSQL server
certificates** and paste a server-generated CSR with the workspace's approved
DNS names and IP addresses. Install the returned PEM on PostgreSQL with the
private key that generated the CSR, then reload TLS. Devices keep their existing
enrollment and trust bundle. The certificate expires within 365 days and within
the issuing CA's lifetime.

The renewal API introduced in schema 45 checks the administrative role, authenticated device session, final
enrollment keys and exact signed policy, account state and trust bundle before
returning the wrapped CA and organisation encryption key to Go. It records a
key-copy release in the existing session audit. Go verifies both copies and
matches the CA private key to the pinned public certificate before signing.
Hardened and Paranoid require a separate custodian flow.

Schema 46 adds rotation for Default and Standard. Submit a server CSR using
**Stage a new workspace CA**. Sign in again to see the staged certificate.
While PostgreSQL serves its existing certificate, let all enrolled devices
receive the signed bundle that trusts both CAs, or choose **Export signed
trust bundle** to distribute it to offline devices. Install the staged
certificate on each configured PostgreSQL endpoint and reload TLS, then choose
**Check installation and retire the previous CA**.

The retirement step requires a fresh verified TLS handshake with each
configured endpoint and compares the exact leaf to the staged certificate.
Publishing retirement advances the signed sequence and removes the previous
root. The device keeps its enrollment, and later renewals use the new CA.
After retirement, sign in and export the current bundle to distribute the new
root alone. A device that missed the transition can choose **Choose signed
trust update** in the protected sign-in window, select the `.whtls` file and
enter its existing account factors. Wormhole verifies the signature and the
workspace's saved sequence, checks the configured hosts, and persists the
new trust before contacting PostgreSQL. The file contains public trust metadata.

Schema 47 adds **Update offline recovery kit** for Default and Standard
administrators using the workspace CA. After retiring the previous CA, sign in
again, select the existing `.whrecovery` kit, then choose a new file. Wormhole
checks the existing kit against the original workspace recovery capsule and
verifies the current CA against the signed trust bundle. Under Standard, confirm
the export in the protected prompt with the Wormhole password and ASK if the
account uses one. Keep the new file with the original recovery code. The audit
records the release of the encrypted CA key copy. Hardened and Paranoid
custodian recovery remains pending.

`CreateWorkspaceCA` requires independently authenticated key-graph coordinates,
organisation encryption public key, organisation signing seed, approved host
names and validity dates. It generates an ECDSA P-256 CA with path length zero,
serverAuth only, critical DNS/IP name constraints and exact IP prefixes. The
32-byte scalar is stored only as an existing HPKE `SignedKeyCopy`; workspace,
CA key, holder and issuer identities are authenticated by that format. The
returned record contains the public certificate and encrypted key copy.

`WrappedWorkspaceCA.IssueServerCertificate` verifies the independently pinned
organisation signature and opens the key copy. It checks that the recovered key
matches the issuer certificate. Callers must enforce current administrator and,
for Hardened+, custodian authorization before invoking it. Historical possession
of an organisation key does not establish current authorization.

Issuance requires a single bounded PEM CSR, a valid proof of possession, an
ECDSA P-256/P-384/P-521 or RSA 2048–8192-bit public key, and a SHA-256-or-stronger
signature. Ed25519, weaker curves, SHA-1, extra PEM objects, requested CA/EKU or
unknown extensions, URI/email/unknown SAN types, wildcard names and duplicate
names are rejected. SANs must exactly match the independently approved set;
DNS case and IP representations are canonicalized. The request's subject is
not copied. No server private key is created or returned.

The issuer must be a currently valid, self-signed P-256 server-only CA with
path length zero and critical permitted name constraints. Leaf certificates
are serverAuth only, valid for at most 397 days and never beyond their issuer.
The completed chain is verified before returning the PEM certificate.

DNS name constraints also permit subdomains; absent name types are unconstrained
by X.509. Therefore constraints complement, rather than replace, the exact
approved SAN set. Clients will additionally need the signed trust bundle's
exact host allowlist and revocation/sequence checks. The certificate in this
record is not independently an organisation-authenticated trust anchor.

Private byte buffers and the exposed ECDSA scalar are wiped on return. Cleanup
is best effort: standard-library cryptographic operations may retain temporary
copies until garbage collection. These functions create no long-lived key
owner, filesystem output, log, network operation or OS trust-store entry.
They do not establish complete Hardened/Paranoid runtime guarantees.

Tests cover encrypted serialization/reload, foreign workspace and wrong key/pin,
tampered copies, substituted CA, zero scalar, DNS-only/IP-only/mixed constraints,
CSR privilege escalation, malformed PEM and proof, validity limits, wrong SANs,
chain constraints, certificate usage and signer failure. The device-certificate
CA and mTLS enrollment are separate delivery work.
