# Fortinet IPsec adversarial review

Scope: shared create/edit UI, native credential IPC, protected persistence,
SAML and SSL fallback, sidecar startup, IKEv1/IKEv2, ESP, DHCP and local LAN.
Baseline: `2b222df50fcb3241a97e77774b1a7d524c2d2d94` plus the existing Fortinet
working diff. No unrelated user edits were present. Initial UI/native tests and
sidecar suite passed. Review is local as required by the simplify skill.

## Finding ledger

Locations below identify the baseline, before review corrections.

| ID | Priority | Location | Evidence and impact | Correction / regression | State |
|---|---|---|---|---|---|
| F01 | P1 | `ipsec.go:236`, `Client.DNS` | DHCP stores DNS in the lease, but the resolver reads only IKE CP. `TestDHCPDNSIsUsedByResolverAndCannotBeMutated` gets an empty list and would select public DNS inside ESP. Internal names fail. | Read the active lease DNS, preserve copy ownership; test lease, expiry and resolver selection. | fixed |
| F02 | P1 | `internal/session/ikeauth.go:298`, final PSK AUTH | A valid PSK AUTH for `vpn.test` establishes even when configured RemoteID is `different.test`. Reproduced by a full offline PSK exchange. | Bind the final responder ID to the configured PSK identity before installing a Child SA. | fixed |
| F03 | P2 | backend `fortinet_ipsec_fallback.go:117` | SSL-stage prompt/context cancellation becomes a generic connection error. Both branches fail `TestSSLFallbackPreservesCancellation`. | Preserve cancellation without returning arbitrary SSL diagnostics. | fixed |
| F04 | P2 | `fortinet_legacy.go:531`, ESP receive | A valid late packet on an expired previous SA signals fatal expiry for the fresh current SA. Reproduced after an ESP key cutover. | Select by SPI and distinguish obsolete from current-key expiry; preserve hard limits. | fixed |
| F05 | P2 | sidecar `main.go:249`, gateway attempt | OnDead during the first attempt cancels the entire startup, so backup is never tried. The fault-injected gateway test visits only the primary. | Scope death to its startup attempt, and promote only the selected live client's callback to the owning lifetime. | fixed |
| F06 | P2 | `fortinet_lan.go:68` | `Prefix.Contains` rejects a scoped IPv6 address; `fe80::1234%Ethernet` goes into the VPN despite local LAN being enabled. | Strip scope only for prefix comparison; retain it for the OS dial. | fixed |
| F07 | P3 | backend `fortinet_ipsec_secrets.go:49` | Each preserved field rereads and decrypts the same profile (up to five times). | Read one protected snapshot lazily and reuse it; preserve existing marker/origin validation. | fixed |
| F08 | P2 | `dataplane.go:200`, control RX | A fatal UDP receive error merely ends demux. With DPD disabled, the owner is not told and the tunnel stays unusable. The raw ESP worker already handles the equivalent failure. | Report unexpected RX termination through the existing death path; cancellation remains quiet. | fixed |
| F09 | P1 | `internal/ikev1/session.go`, active Quick Mode dispatcher | Forged Quick Mode changes CBC/rekey state and can fail a live SA; final QM3 loss cannot recover, and completed exchange IDs are not retained across rekeys. Negative packet/state tests reproduce it. | Authenticate before mutation, require QM payload shape, retain bounded completed IDs and resend byte-identical cached replies. | fixed |
| F10 | P2 | `internal/ikesa/keys.go`, `internal/session/rekey.go` | Key schedules admit nonces beyond 256 bytes; a SHA512 Child SA accepts 16-byte rekey nonces, violating RFC 7296 2.10/3.9. Tests exercise both request and response bounds. | Centralize nonce validation for negotiated PRF and enforce bounds before installing a Child SA; keep length diagnostics accurate for both too-short and oversized inputs. | fixed |
| F11 | P2 | sidecar `main.go:244`, additional gateway selection | Bracketed IPv6 is normalized only for the primary. The actual failover test observes `[[2001:db8::2]]:500`, so every such backup fails. | Reuse one IPv6 host normalizer at each prepared attempt; run primary/backup IPv6 regression. | fixed |

Each adversarial cycle covers behavior/contracts, hostile inputs, atomic state,
concurrency/lifetime, authorization/secrets, integration/platform drift,
operability and tests that can pass for the wrong reason. Implementation edits
start only after the complete cycle has been inspected and candidates validated.

## Rejected or bounded candidates

- No direct-route fallback was found: SSL starts another VPN; LAN bypass requires
  explicit enablement and a connected subnet. Hostname DNS remains inside ESP.
- DHCP MAC persistence/reservations would require an additional device-identity
  policy not requested by the profile options; dynamic DHCP is the current scope.
- The invalid custom NAT-T test port cannot be supplied by a Wormhole profile;
  it is not evidence of a production leak in the application's startup path.
- Certificate/EAP is a Fortinet-specific exchange, not RFC 4739. Offline peer
  tests establish state/crypto contracts, not real FortiGate interoperability.
  No protocol change is justified by guessing a proprietary wire exchange.
- No gateway credentials or live FortiGate/IdP environment were supplied; live
  interoperability and privileged raw ESP remain explicit integration limits.

## Completed gates

All eleven accepted findings are fixed. Initial failing reproductions and the
later corrected fixtures are retained as regression tests. The Quick Mode
history-cap fixture now enters the real pending state before calling finish;
the lost-final-packet fixture captures QM2 from Send, not cleared lastSent state.
The control-receive test supplies a real dummy ESP tunnel so a worker panic
cannot produce a false success.

The first clean adversarial run was followed by mandatory simplify review,
which found F11. Counters reset after F11 and after correcting F10's stale nonce
diagnostic. On the final implementation the following local cycles completed:

| Cycle | Independent checks | Result |
|---|---|---|
| Adversarial 1 | Requirements and shared UI through native secret IPC, protected writes, fallback identity, sidecar preparation, wire authentication and data-plane limits. All eight attack lanes: contracts, hostile bounds, atomicity, lifetime/races, secrets, platform/interfaces, bounded work/operability and test resistance. | Clean 1/2 |
| Adversarial 2 | Reverse order from negative wire/runtime tests to their real callers: forged/retyped/replayed QM, retransmission loss, nonce bounds under SHA512, old/current ESP expiry, DHCP DNS/lease failure, scoped IPv6 and bracketed backup gateways, cancellation and credential markers. Rechecked all eight lanes and platform compilation. | Clean 2/2 |
| Simplify 1 | Reuse: shared CBC/PRF descriptor, nonce validator and gateway normalizer. Efficiency: one protected snapshot, bounded histories/queues and no redundant network path. Quality/bugs: parser limits, identity binding, immutable DNS ownership and negative matrix tests. | Clean 1/3 |
| Simplify 2 | Reuse: shared create/edit settings and public IPC contract. Efficiency: connected-prefix refresh, callback/cancellation ownership, per-attempt timeouts. Quality/bugs: primary/backup IPv6 parity, SAML issuer binding, SSL fingerprint rechecks and native authorization cleanup. | Clean 2/3 |
| Simplify 3 | Reuse: existing session/ESP rekey and tunnel lease mechanisms. Efficiency: cache bounds and hot-path allocation/I/O review. Quality/bugs: old-SA grace, hard limits, DPD-disabled RX death, race-detector results, false-positive fixture resistance and the final diff. | Clean 3/3 |

The protocol review closed before the later provider-scoped alignment fix,
which has separate native layout coverage. Speculative broad
abstractions across TS and Go, caching LAN prefixes (would retain stale routes),
and caching/de-duplicating SAML and IKE gateway attempts (different token issuer
contracts) were rejected. Existing library metadata getters after Close do not
permit network use: application dials fail closed and the lease owner closes
streams; changing their general lifetime semantics is outside this review.

## Final verification

- Full `npm run test:electron`: passed, including the backend and IPsec-engine
  suites. Focused Fortinet UI/native/auth tests: 142 passed, none skipped.
- Vendor engine `go test -race -coverpkg=./... -coverprofile=coverage.out ./...`:
  passed. Sidecar `go test -race -coverprofile=coverage.out ./...`: passed.
- Backend `go test ./...`: passed; focused Fortinet/fallback/tunnel coverage
  suite passed. `go vet ./...` passed in all three affected Go modules.
- Changed Go statements: **84.49% (1100/1302)**, above the required 80%.
  Duplicate cross-package coverage blocks are merged using the maximum hit
  count; blocks intersecting added/modified lines and new production Go files
  are counted once. The filtered profile passes the project's
  `parseGoCoverage` / `meetsCoverageThreshold` gate in `scripts/test-coverage.ts`.
- Shared Fortinet state module: 100% lines/functions, 97.73% branches under
  Node's coverage gate. TSX/process-entry coverage exclusions are explained in
  WORMHOLE.md and backed by source contracts and real sandboxed native fixtures.
- Renderer production build, renderer typecheck, Electron TypeScript build,
  scoped format check and Go formatting: passed.
- Sidecar compilation: Windows amd64/arm64, Linux amd64 and Darwin arm64 passed.
- Dependency-security suite: 53 passed, five existing conditional skips.
- Scoped lint: no errors; 16 existing App.tsx warnings in unrelated React code.
  Git's global ignore file is unreadable in this environment; it does not
  prevent diff checks or tests. The Chromium fixture passed with sandboxing
  enabled after restoring read/execute ACLs on the local Electron runtime.
- `git diff --check`: passed. Temporary scripts, profiles, logs and binaries
  removed. At that review stage, no commit, push or publication was requested.

Live FortiGate/IdP interoperability, proprietary certificate/EAP policy and
privileged raw ESP on actual operating systems remain manual integration
checks. Offline peers and cross-compilation do not establish those results.

## PR preparation

The publication branch integrates main through `9ec0e48d` without conflicts.
The resulting PR diff contains only Fortinet implementation, tests and docs;
upstream release, shutdown, SMB and OpenVPN fixes remain intact.

Complete-PR Go coverage against `origin/main...HEAD`, including imported IKEv1
source blocks rather than excluding them: **84.10% (2809/3340)**. The same
source-block merge and project threshold gate described above are used. The
84.49% measurement above describes the narrower post-snapshot extension/review
delta, not the entire PR.

The later Fortinet VPN-settings alignment fix is provider-scoped. Its real
Chromium fixture verifies equal label/control tops at 1024px and 800px, stacked
fields at 600px, hint/fallback separation, and 100% execution coverage of the
modified mounted section. Renderer/Electron TypeScript checks, renderer build,
Go race tests, formatting/lint and cross-platform sidecar builds were repeated
after integrating main. Full-suite results are listed in the PR description.

Publication verification limitation: two complete npm suite runs fail
`TestFortinetIPsecSAMLAndNativePayload` while closing the test sidecar
(`IPsec sidecar survived lease release`). Standalone backend `go test ./...`
passes, as do five isolated repetitions of that test and fifteen repetitions
with the race detector. The cause of the full-run-only failure is unconfirmed;
no timeout or assertion has been relaxed. PR #530 remains draft and reports the
complete suite as failing, rather than treating isolated passes as closure.
