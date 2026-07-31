# Adversarial ledger — UpdateChecker channel

**Scope:**
- `rust/crates/wormhole-update/src/channel.rs` — `UpdateChecker`, `NetworkStubUpdateChecker`,
  `FakeUpdateChecker` / `FakeSeenRequest` / `FakeUpdateOutcome`, `UpdateApiToken`,
  `UpdateCheckRequest`, `check_for_update_network_stub`, `UPDATE_CHECK_NETWORK_GAP`
- Docs: `docs/migration/13-update-logging.md` (channel section), this ledger + `README.md`

**Out of scope:** live GitHub HTTP / installer UX / MOTW / cache rotation; version/download/SHA
paths already closed in [`adversarial-ledger-update-logging.md`](adversarial-ledger-update-logging.md);
wiring `SharedUpdateChecker` into `AppServices` (hosts inject later).

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** NetworkStub fail-closed / no sockets; API token never in `Debug`/`Display`;
Fake empty (and exhausted) queue fail-closed; Fake records token presence/len only.  
**Baseline:** `cargo test -p wormhole-update` — 42 green before review  
**Final:** **46** green  

Compared against C#: `IUpdateService.CheckAsync` / `UpdateService` transport-failure →
`UpdateCheckResult.Failed` (no advertised update); no PAT logging.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-update` | **pass** (46) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### UCH-01 — Exhausted Fake script fail-closed under-tested (`P2`) — **fixed**

- **Where:** `FakeUpdateChecker::check` empty-queue branch
- **Invariant:** Empty **or exhausted** script → `UpdateCheckResult::failed` (never advertise)
- **Evidence:** Only cold-empty `FakeUpdateChecker::new()` was pinned; depleting a scripted update then checking again was unproven
- **Fix / regression:** `fake_exhausted_script_fail_closed_again`

### UCH-02 — Absent / empty token presence recording under-pinned (`P2`) — **fixed**

- **Where:** `FakeSeenRequest::from_request`
- **Invariant:** Records presence/len only; `None` and `Some("")` → absent / len `0`; never retain value
- **Evidence:** Tests only covered non-empty PATs
- **Fix:** Clarify empty→absent in docs + shared `filter(|t| !t.is_empty())`; `fake_records_absent_and_empty_token_presence_only`

### UCH-03 — Debug/Display secret-oracle discipline under-pinned (`P2`) — **fixed**

- **Where:** `UpdateApiToken` / request Debug tests (Bitwarden BS-04 parity)
- **Invariant:** Assert secrets via `expose()`, never treat `format!("{:?}", token)` as the value
- **Fix:** `assert_ne!(dbg/disp, expose())`; unicode token Debug never echoes value; free-stub `Display`/`Debug` must not echo PAT
- **Regression:** strengthened `api_token_debug_and_display_redact`, `api_token_unicode_len_is_utf8_bytes_value_never_in_debug`, `free_network_stub_errors`

### UCH-04 — NetworkStub hostile / repeated check under-pinned (`P2`) — **fixed**

- **Where:** `NetworkStubUpdateChecker`
- **Invariant:** No sockets; ignore owner/repo/arch/token; never advertise across repeated calls
- **Evidence:** Crate has no HTTP/socket deps; happy-path stub test only
- **Regression:** `network_stub_hostile_fields_still_fail_closed_no_sockets`

### UCH-05 — Channel ledger / doc drift (`P3`) — **fixed**

- **Where:** `13-update-logging.md`, `README.md`, NetworkStub rustdoc
- **Evidence:** No channel-specific ledger; Fake empty-token semantics undocumented; NetworkStub claimed “never reads” while observing `len`
- **Fix:** This ledger + README row; doc empty/`None` presence note; rustdoc “ignore values / may observe length”

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Live `HttpClient` / GitHub `releases/latest` — explicit non-goal |
| REJ-02 | — | `AppServices` field for `SharedUpdateChecker` — hosts inject later; bootstrap only links crate |
| REJ-03 | — | Zeroize PAT on `Drop` — hardening beyond C# / stub surface |
| REJ-04 | — | Async `UpdateChecker` + cancellation — sync stub matches library surface; UI host later |
| REJ-05 | — | Shared `ignore_api_token` helper for stub + free fn — two one-liners; not worth abstraction |
| REJ-06 | — | Treat whitespace-only token as absent — non-empty UTF-8 is “present”; value still never retained |
| REJ-07 | — | Concurrent Fake stress test — single `Mutex` (no Bitwarden-style multi-lock deadlock) |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → security → boundaries → test resistance → docs | UCH-01…05 | Fixed; reset |
| Adv-2 | Security → boundaries → concurrency → docs accuracy | UCH-05 wording | Fixed with docs; reset |
| Adv-3 | Security-first re-read | None | Clean (1/2) |
| Adv-4 | Tests-as-oracles → C# Failed parity → integration drift | None | Clean (2/2) |
| Adv-5 | Post-simplify delta: `from_outcomes` extend / stub ignore / presence oracle | None | Clean (1/2 re-run) |
| Adv-6 | Attack checklist: no sockets / Debug / empty queue / presence-len | None | Clean (2/2 re-run) |

---

## Iterative-review-simplify cycles

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Reject shared ignore helper | Batch `from_outcomes` under one lock | Drop unused owner/repo binds on NetworkStub | **Fixed** |
| 2 | — | Scoped lock block vs `drop` | Remove redundant `assert_ne` | **Fixed** |
| 3 | — | — | Strengthen presence test secret (`ghp_presence_probe_only`) | **Fixed** |
| 4 | No findings | No findings | No findings | **clean 1** |
| 5 | No findings | No findings | No findings | **clean 2** |
| 6 | No findings | No findings | No findings | **clean 3** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-update
```

Expected: **46** passed (13 channel + prior version/download/check coverage).

Focused: `cargo test -p wormhole-update --lib channel::`

---

## Residual / out-of-scope notes

- Live HTTP checker still returns via `UPDATE_CHECK_NETWORK_GAP` / `CheckNetworkStub` until a host-supplied client lands.
- `check_for_update_network_stub` returns `Err(CheckNetworkStub)`; `NetworkStubUpdateChecker` returns `Ok(failed)` (C# `CheckAsync` shape). Both fail closed.
- App bootstrap logs arch + placeholder version only; it does not call GitHub.
