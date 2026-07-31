# Adversarial ledger — SSH host-key verify-on-connect

**Scope:** `rust/crates/wormhole-ssh/src/host_key_verify.rs` (`verify_host_key_on_connect` / `HostKeyConnectVerdict` / `HostKeyMismatchPolicy` / `HostKeyRejectReason`), session wrappers in `rust/crates/wormhole-session/src/host_key.rs` (`verify_ssh_host_key` / `_fake`), Fake store (`FakeKnownHosts`) decision path only  
**Out of scope:** `known_hosts.rs` store internals ([adversarial-ledger-ssh-known-hosts.md](adversarial-ledger-ssh-known-hosts.md)); prompt Accept/Reject glue ([adversarial-ledger-known-hosts-prompt.md](adversarial-ledger-known-hosts-prompt.md)); agent ↔ auth select; live SSH; GPUI/WinUI  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Impl:** `ecc03638-a07a-41df-8de9-f58c43833cb6`  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh -p wormhole-session` green before hardening.
- Context7 MCP unavailable; C# `SshHostKeyValidator` / `SshSessionService.HostKeyReceived` used as decide/mismatch authority (C# silent TOFU on unknown is intentional Lab divergence → Prompt).
- No live SSH / no HardwarePass claims in this review.

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Accept / Reject / Prompt verdicts | **Held** |
| `HostKeyMismatchPolicy` Reject default (C# parity) / Prompt lab overwrite | **Held** |
| Session wrappers + empty host fail-closed | **Held** — before `:port` identity |
| Fake store; pure decision (no pin / no dial) | **Held** |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| HV-A1 | P2 | `host_key_verify` tests | Empty fingerprint with existing pin could regress to `Ok(Reject)` if early empty check dropped (`decide` soft-Mismatch) | **Fixed** — `empty_fingerprint_with_existing_pin_still_errs` |
| HV-A2 | P2 | `host_key_verify` tests | Invalid / whitespace / hostile host fail-closed undocumented by verify-local regressions | **Fixed** — dedicated fail-closed tests |
| HV-A3 | P2 | `host_key_verify` tests | Purity contract (Prompt/Reject must not mutate store) unpinned | **Fixed** — mismatch/unknown/prompt no-mutate regressions |
| HV-A4 | P2 | `host_key_verify` / session | Trim + case-fold lookup; session whitespace host before `:port` untested | **Fixed** — `host_trimmed_and_case_folded_for_lookup`, `verify_whitespace_host_fails_closed_before_port`, `verify_reject_does_not_pin` |
| HV-S1 | — | `Reject.known_fingerprint` | `Option` always `Some` for sole `Mismatch` reason | **Simplified** — `String`; prompt Reject arm drops `unwrap_or_default` |
| HV-S2 | — | `verify_host_key_on_connect` | Cloned known pin on Trust/Unknown | **Simplified** — borrow through `decide`; allocate only on mismatch |
| HV-S3 | — | session wrappers | `Ok(...?)` noise | **Simplified** — `.map_err(SessionError::from)` |
| HV-R1 | — | Unknown → Prompt | C# silent TOFU (`CanTrust = true`) | **Rejected** — documented LabOnly; product TOFU deferred |
| HV-R2 | — | Client `accept_server_host_key` | Still separate from verify glue | **Rejected** — LabOnly / spike path; orchestrator wiring Pending |
| HV-R3 | — | `host:port` as bare session host | Double identity | **Rejected** — gate docs require bare host; same as prompt ledger |
| HV-R4 | — | Custom `HostKeyPinStore` empty pin | `decide(Some(""))` → Tofu / Prompt | **Rejected** — Fake/file stores validate on pin; speculative |

## Simplify deltas (after adversarial)

- `HostKeyConnectVerdict::Reject.known_fingerprint: String`
- Avoid Trust/Unknown fingerprint clone
- Session verify/gate `map_err(SessionError::from)`

## Regression coverage added

- Empty fingerprint with pin still `Err` (not Reject)
- Invalid / whitespace fingerprint + hostile host fail-closed
- Prompt/Reject purity (store unchanged)
- Host trim + case-fold Trust
- Session whitespace host fail-closed before `:port`; reject does not pin
- Existing Accept / unknown Prompt / mismatch Reject|Prompt / empty host retained

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh -p wormhole-session
```

**Result (final):** green (wormhole-ssh lib + wormhole-session; 1 ignored live SSH client test).

## Gate confirmation

- Adversarial clean passes: **2** (independent lane orderings; **renewed** after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
