# Adversarial ledger — Auto-sudo session glue

**Scope:** `rust/crates/wormhole-ssh/src/auto_sudo_glue.rs` (`AutoSudoSessionGlue` /
`AutoSudoPassword` / `AutoSudoTerminal` / FakeTerminalSession sink), exports in
`wormhole-ssh` `lib.rs`, docs `06-ssh-spike.md` (session glue), `14-terminal-bridge.md`
(glue stub row), `feature-matrix.md` (Auto-sudo lab row), note in
[adversarial-ledger-clipboard-auto-sudo.md](adversarial-ledger-clipboard-auto-sudo.md)

**Out of scope:** detector internals (`auto_sudo.rs` — closed in clipboard-auto-sudo
ledger); live SSH shell / WebView2 pump / GPUI; `wormhole-tunnels` /
`wormhole-surface-win`; HardwarePass

**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles
(adversarial renewed after simplify edits → 2 clean again)

## Baseline

- `cargo test -p wormhole-ssh` — 114 passed + 1 ignored (pre-review; `elevation_payload` dead_code warning)
- `cargo test -p wormhole-terminal` — 68 passed
- Context7 MCP unavailable; C# `SshAutoSudoDriver.cs` is state-machine authority
- No live SSH in this review

## Attack criteria (user)

| Criterion | Result |
|---|---|
| First output → `sudo su\r` | **Held** — first non-empty chunk not tailed; writes `ELEVATION_COMMAND` + `LINE_TERMINATOR` |
| Rolling prompt classify → optional password inject | **Held** — `SudoPromptTail` + detector; password out-of-band once |
| Timeout clears secret without send | **Held** — `on_timeout` → `FinishedWithoutPassword`; elevation-only writes |
| `AutoSudoPassword` Debug redaction | **Held** — `[REDACTED]` + `utf8_len` only; glue Debug is phase / has_password / tail |
| FakeTerminalSession sink | **Held** — `on_output_fake` / `FakeTerminalSink` |
| Docs 06 / 14 / feature-matrix / clipboard ledger note | **Held** |

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| ASG-001 | P1 | `on_output` WaitingForShell | Sync elevation write `Err` left `WaitingForPassword` + secret armed; ignoring `Err` could inject without successful `sudo su` | C# relies on async write + 10s timeout backstop; stub has no internal timer | **Fixed** — `finish_internal` on elevation write `Err`; regression `closing_session_elevation_write_fails_closed` |
| ASG-002 | P2 | password write path | Mid-session close after elevation: secret clear / no sink bytes / error omits payload untested | `close_after_n_writes(1)` | **Fixed** — `password_write_failure_clears_secret_without_send` |
| ASG-003 | P2 | glue ↔ detector | CRLF-terminated sudo prompt not exercised through glue | Detector had coverage; glue path missing | **Fixed** — `crlf_terminated_prompt_injects_via_glue` |
| ASG-004 | P2 | first shell chunk | Prompt-shaped first chunk must not linger in tail and fire inject on next ordinary chunk | C# does not append first chunk | **Fixed** — `first_chunk_prompt_text_is_not_tailed` |
| ASG-005 | P3 | `elevation_payload` | Dead code outside `cfg(test)` (lib warning) | `cargo test` lib warn | **Fixed** — helper folded into test-only `line_bytes` / `elev_bytes` |
| ASG-006 | P3 | `AutoSudoPassword` | `Clone` duplicated secrets without need | No callers required Clone | **Fixed** — removed `Clone` |
| ASG-007 | P3 | docs / steps | Fail-closed write semantics + idempotent timeout/finish under-documented | 06 / 14 / step rustdoc | **Fixed** — docs + `timeout_and_finish_are_idempotent_when_done` |
| ASG-R1 | — | Live shell / GPUI / subscribe+Timer | Stub non-goal | Spike Pending | **Rejected** — documented residual |
| ASG-R2 | — | Empty password → send `\r` | Same as C# `SendLine("")` | Driver parity | **Rejected** |
| ASG-R3 | — | Internal mutex / reentrancy | Single-threaded sync stub | Live wiring owns affinity | **Rejected** — out of stub scope |
| ASG-R4 | — | Zeroize-on-drop | C# `string?` parity for stub | Secrets-win patterns elsewhere | **Rejected** — stub scope |

## Simplify deltas (after adversarial)

- Glue `Debug`: drop redundant `password: Some("[REDACTED]")`; keep `has_password` + phase + tail
- Remove unused `Default` (empty-password footgun)
- `AutoSudoPassword` Debug uses `utf8_len()`; tests share `line_bytes`

## Regression coverage added

- Elevation write fail-closed (secret cleared; no later inject)
- Password write failure: no sink bytes, error omits payload, `Done`
- CRLF prompt through glue
- First-chunk prompt text not tailed
- Timeout / finish idempotent when `Done`
- Existing elevation / inject-once / timeout / banner / Debug / dyn sink tests retained

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | ASG-001…ASG-003, ASG-005, ASG-007 | Fixed; reset |
| Adv-2 | Reverse: security → integration → state → boundary | ASG-004, ASG-006 + doc/step clarity | Fixed; reset |
| Adv-3 | Contract → concurrency → perf → tests; `--no-default-features` | None | Clean (1/2) |
| Adv-4 | C# line-by-line parity + privacy + extremes | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Test `line_bytes` shared | Hot path unchanged | Glue Debug redundancy | Yes → reset | Fixed |
| Sim-2 | `utf8_len()` in Debug | No Clone copies | Drop unused `Default` | Yes → reset | Fixed |
| Sim-3 | Detector-only classify; thin Fake sink | Single alloc per write_line | Defensive None branch kept | None | Clean (1/3) |
| Sim-4 | Elevation vs dyn path tests complementary | Sync tests fast | No brittle prod churn | None | Clean (2/3) |
| Sim-5 | Exports sufficient | No extra I/O | Fail-closed comments accurate | None | Clean (3/3) |

### Adversarial renewal (after simplify)

| Cycle | Focus | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Debug delta / Default removal / fail-closed intact | None | Clean (1/2) |
| Adv-R2 | Privacy of glue Debug; explicit `new` password required | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features --lib auto_sudo
cargo test -p wormhole-terminal
```

**Result (final):** `wormhole-ssh` 128 passed + 1 ignored; `--no-default-features --lib auto_sudo` 29 passed (detector + glue); `wormhole-terminal` 68 passed. No `elevation_payload` dead_code warning. `git diff --check` clean on touched paths.

## Remaining blockers

- Live auto-sudo against a real SSH shell / WebView2 pump / GPUI (glue + FakeTerminalSession only).
- Caller must arm the 10s prompt timer and treat sync write `Err` as fail-closed (cancel timer; do not keep feeding output expecting inject).
