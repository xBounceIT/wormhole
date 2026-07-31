# Adversarial ledger — SSH agent availability probe

**Scope:** `rust/crates/wormhole-ssh/src/agent.rs` (`is_agent_available` / `FakeAgent` / `PlatformAgentProbe`), agent exports in `lib.rs`, Agent auth fail-closed interaction in `auth.rs` / `client.rs` (no rewrite of auth beyond verifying stubs), agent section of `docs/migration/06-ssh-spike.md`  
**Out of scope:** `known_hosts.rs` (do not rewrite); Pageant; real agent wire auth  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh` — green (65 passed + 1 ignored before agent hardening).
- `cargo test -p wormhole-ssh --no-default-features` — green (agent probe always on).

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Probe never speaks agent protocol beyond open | **Held** — named-pipe `OpenOptions` open+drop only; no read/write of SSH2_AGENT_* |
| `ERROR_PIPE_BUSY` ⇒ present | **Held** — raw OS 231 (+ sharing 32 / access-denied 5) |
| Fake deterministic | **Held** — `FakeAgent` in-memory; regression `fake_agent_is_deterministic` |
| Agent auth fail-closed before dial | **Held** — `ensure_auth_method_supported` + `AuthNotImplemented("agent")`; `connect_agent_stub_fails_before_network` |
| No secrets logged | **Held** — `source` is static labels only; Debug has no key/password fields |
| Windows pipe path not from hostile env without bounds | **Fixed** — named-pipe-only `SSH_AUTH_SOCK` with length / name bounds; UNC / FS / other devices ignored |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| SSH-AG1 | P1 | `agent.rs` `probe_platform` / `SSH_AUTH_SOCK` | Hostile env could point at UNC / `\\.\` devices (hang / open arbitrary devices) with no bounds | **Fixed** — `classify_windows_agent_pipe` accepts only `\\.\pipe\NAME` / `//./pipe/NAME` with safe NAME; ≤256 bytes; else ignore env |
| SSH-AG2 | P1 | `probe_windows_endpoint` (former) | Env FS paths opened read+write (false positives / unnecessary file opens) | **Fixed** — Windows env path is named-pipe-only; open+drop only after validation |
| SSH-AG3 | P2 | `classify_windows_probe_error` | `PermissionDenied` ⇒ present applied to any Windows open target | **Fixed** — classifier only used for validated named pipes; raw 5/32/231 present, 2/3 absent |
| SSH-AG4 | P2 | LocalFs `exists()` (interim) | Absolute FS `SSH_AUTH_SOCK` (e.g. `C:\Windows`) would false-positive | **Fixed** — dropped Windows FS endpoints; pipe-only |
| SSH-AG5 | P2 | Non-Windows `SSH_AUTH_SOCK` | Relative / `..` paths were CWD-dependent | **Fixed** — require absolute path, reject `ParentDir` |
| SSH-AG6 | P3 | docs `06-ssh-spike.md` | Bounds / pipe-busy / fail-closed semantics underspecified | **Fixed** |
| SSH-AGR1 | — | Pageant not probed | Documented non-goal | **Rejected** — out of scope |
| SSH-AGR2 | — | `\\?\pipe\…` form rejected | Fall through to default OpenSSH pipe | **Rejected** — spike accepts `\\.\` / `//./` forms only |
| SSH-AGR3 | — | Connect+drop may briefly appear in agent logs | No protocol bytes; availability-only | **Rejected** — acceptable for open-only probe |

## Simplify deltas (after adversarial)

- Flattened Windows endpoint enum to pipe-only classifier.
- `classify_windows_pipe_probe_error` prefers raw OS codes then `PermissionDenied` kind.
- Non-Windows absolute / no-`..` guard (SSH-AG5).
- `FakeAgent`: `PartialEq` + deterministic regression test.
- Docs table: Windows bounds + non-Windows absolute contract.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
```

**Result (final):** default features — 72 passed + 1 ignored (live server); `--no-default-features` — 46 passed. Agent module: 15 unit tests on Windows (FakeAgent offline; pipe classifier / hostile env cases).

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- `known_hosts.rs` untouched.
