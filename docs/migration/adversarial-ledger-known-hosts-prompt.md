# Adversarial ledger — SSH known_hosts prompt glue

**Scope:** `rust/crates/wormhole-ssh/src/host_key_prompt.rs` (`resolve_host_key_prompted` / `HostKeyPrompt` / `FakeKnownHosts` / `FakeHostKeyPrompt`), `HostKeyRejected` contract in `error.rs`, `rust/crates/wormhole-session/src/host_key.rs` (`gate_ssh_host_key` / `gate_ssh_host_key_fake`), docs `06-ssh-spike.md` (prompt section) + `16-session-orchestrator.md` (SSH host-key stub row)  
**Out of scope:** `known_hosts.rs` store internals (closed in [adversarial-ledger-ssh-known-hosts.md](adversarial-ledger-ssh-known-hosts.md)); live SSH; GPUI/WinUI dialog  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh -p wormhole-session` — green before prompt hardening (83 + 1 ignored SSH; 18+33 session).
- Context7 MCP unavailable; C# `SshHostKeyValidator` / mismatch exception used as fingerprint authority only.
- No live SSH in this review.

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Accept pins / Reject fail-closed | **Held** — unknown Accept → `set_pin`; unknown Reject → `HostKeyRejected`; changed Reject → `HostKeyMismatch`, pin unchanged |
| Changed Accept may overwrite after explicit accept | **Held** — regression `changed_accept_overwrites_pin` + session gate |
| `FakeKnownHosts` / scripted prompt; no live SSH | **Held** |
| Debug fingerprints only (no raw keys) | **Held** — request/store Debug + regressions; `FakeHostKeyPrompt` Debug omits payloads |
| Session `gate_ssh_host_key` / `_fake` | **Held** — bare host + port → `host_identity` then glue |
| Docs 06 / 16 | **Held** — reject error split + orchestrator stub / `ssh_accept_any_host_key` noted |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| KP-A1 | P2 | `HostKeyPinStore` for `KnownHostsStore` | Prompt Accept save-failure rollback untested on glue path (only `accept()` had coverage) | **Fixed** — `file_store_accept_save_failure_rolls_back` + `file_store_changed_accept_save_failure_restores_pin` |
| KP-A2 | P2 | `resolve_host_key_prompted` | Invalid fingerprint / hostile host could be assumed to skip prompt without regressions | **Fixed** — `invalid_fingerprint_no_prompt` + `hostile_host_no_prompt` |
| KP-A3 | P2 | `SshError::HostKeyRejected` | Docs claimed reason `"changed"` but Changed+Reject returns `HostKeyMismatch` | **Fixed** — error docs + `06-ssh-spike.md` reject table (Mismatch keeps expected/actual) |
| KP-A4 | P2 | `resolve_host_key_prompted` | Leading/trailing host whitespace passed through to prompt payload while lookup normalized | **Fixed** — trim after validate; `host_trimmed_before_prompt_and_pin` |
| KP-A5 | P2 | `wormhole-session` `host_key` | Missing unknown-reject / changed-accept session-gate coverage | **Fixed** — `reject_unknown_fail_closed` + `accept_changed_overwrites_via_session_gate` |
| KP-A6 | P3 | `FakeHostKeyPrompt` | Exhausted queue fail-closed untested | **Fixed** — `fake_prompt_exhausted_queue_rejects` |
| KP-A7 | P3 | docs `16-session-orchestrator.md` | Stub could be read as wired into orchestrator connect | **Fixed** — note `ssh_accept_any_host_key` until UI prompt wired |
| KP-R1 | — | Orchestrator not calling gate | Stub until dialog | **Rejected** — documented Pending |
| KP-R2 | — | `host:port` + separate port → double identity | Bare-host callers today | **Rejected** — gate docs require bare host; speculative |
| KP-R3 | — | Fingerprint length / DoS | Same validators as store | **Rejected** — store-scope; prior known_hosts ledger |

## Simplify deltas (after adversarial)

- `HostKeyPromptRequest` / `FakeKnownHosts`: derive `Debug` (fingerprint-safe; drop identical hand-rolled impls).
- Mismatch path: fail-closed `ok_or_else` instead of empty-string `unwrap_or_default` if invariant ever breaks.

## Regression coverage added

- Invalid fingerprint / hostile host → no prompt
- Host trim before prompt + pin
- Case-insensitive host Trust through glue
- Exhausted fake prompt queue rejects
- File-store Accept save failure rollback (TOFU + changed)
- Session gate unknown reject / changed accept
- Existing Trust / Accept / Reject / Debug fingerprint tests retained

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh -p wormhole-session
cargo test -p wormhole-ssh --no-default-features --lib host_key_prompt
```

**Result (final):** `wormhole-ssh` 101 passed + 1 ignored (live server); `wormhole-session` 20 unit + 34 orchestrator fakes; prompt module 18 tests under `--no-default-features`.

**Residual warning (out of scope):** `auto_sudo_glue::elevation_payload` dead_code — unrelated to prompt glue.

## Gate confirmation

- Adversarial clean passes: **2** (independent lane orderings; renewed after simplify Debug derive).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- `known_hosts.rs` store algorithm untouched (only used via `HostKeyPinStore` / validators).
