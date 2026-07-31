# Adversarial ledger — HTTP/HTTPS nav-result report glue

**Scope:**
- `rust/crates/wormhole-http/src/nav_report.rs`
  (`NavigationOutcome` → `HttpSessionNavStatus` / `FakeWebViewSurface` /
  `HttpNavSession` / `apply_navigation_report` / `validate_navigate_uri`)
- Exports in `wormhole-http` `lib.rs`; `HttpError::EmptyNavigateUri`
- Docs: `docs/migration/10-http.md`, `interop-inventory.md`, README ledger index

**Out of scope:** Live WebView2 / GPUI; SOCKS reachability probe after
`transport_failure`; AlwaysAllow COM subscribe; `wormhole-session` `SessionHandle`
wiring; C# `WebBrowserView` / `HttpSessionViewModel` edits.

**Authority:** full adversarial-review-fix (edit in scope)  
**Impl:** `8f10b625-7c74-4a0f-b555-95374cd6fadb`  
**Baseline:** `cargo test -p wormhole-http` 52 green (12 `nav_report`)  
**Final:** `wormhole-http` **55** green (**15** `nav_report`)

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (Adv-3/4) + **2** post-simplify re-adv |
| Iterative-review-simplify clean passes | **3** consecutive (after Sim-1 rustdoc fix) |
| `cargo test -p wormhole-http` | **pass** (55) |

---

## Accepted findings

### HNR-01 — Cancel-then-success/fail under-pinned (`P2`) — **fixed**

- **Where:** `nav_report.rs` tests
- **Invariant:** C# `OperationCanceled` keeps waiting; a later real success/fail
  while still `Connecting` must apply
- **Evidence:** Only `cancel_keeps_connecting` existed — no follow-on completion
- **Impact:** Regressions that treat cancel as terminal would slip through
- **Fix:** `cancel_then_success_or_fail_still_applies`
- **Regression:** that test

### HNR-02 — Fake-surface whitespace fail-closed under-pinned (`P2`) — **fixed**

- **Where:** `FakeWebViewSurface::navigate` tests
- **Invariant:** Empty **and** whitespace-only URIs fail closed with no surface
  mutation (same `validate_navigate_uri` as `begin`)
- **Evidence:** Surface test used only `""`; whitespace covered only on `begin`
- **Fix:** Whitespace reject + unchanged count/policy assertions on Fake surface
- **Regression:** extended `fake_surface_preserves_cert_policy_and_rejects_empty`

### HNR-03 — Failed path IgnoreErrors not pinned (`P2`) — **fixed**

- **Where:** `nav_report.rs` tests
- **Invariant:** Report mapping must not mutate `HttpCertPolicy` (success/cancel
  already pinned IgnoreErrors; fail used Default-only target)
- **Fix:** `failed_report_preserves_ignore_cert_policy`
- **Regression:** that test

### HNR-04 — Late cancel / disconnect-while-Connecting gaps (`P3`) — **fixed**

- **Where:** `nav_report.rs` tests
- **Invariant:** Late `Cancelled` must not demote Connected; disconnect while
  Connecting blocks later success (C# teardown / non-Connecting gate)
- **Fix:** Extend `late_reports_ignored_when_not_connecting`; add
  `disconnect_while_connecting_blocks_later_success`
- **Regression:** those tests

### HNR-05 — `navigate_and_report` empty-URI rustdoc dishonest (`P2`) — **fixed**

- **Where:** `HttpNavSession::navigate_and_report` rustdoc; `10-http.md`
- **Invariant:** `begin` rejects empty and the held target is immutable — empty
  fail-closed for ad-hoc targets is on `FakeWebViewSurface::navigate`
- **Evidence:** Docs claimed empty fail-closed “while already begun”
- **Fix:** Honest rustdoc + `10-http.md` wording

### HNR-06 — Interop inventory omitted nav-report (`P3`) — **fixed**

- **Where:** `interop-inventory.md` §9.4 HTTP row
- **Invariant:** Spike note should name Fake nav-result→status glue (feature-matrix
  already did)
- **Fix:** Row text updated

### HNR-07 — Unicode White_Space (NBSP) fail-closed under-pinned (`P3`) — **fixed**

- **Where:** `validate_navigate_uri` / `empty_uri_fail_closed_on_begin`
- **Invariant:** `str::trim` White_Space (incl. NBSP) fails closed like ASCII blanks
- **Fix:** NBSP assertion on `begin`
- **Regression:** that assertion

### HNR-08 — Module rustdoc overclaimed “errors never carry” (`P3`) — **fixed** (simplify)

- **Where:** `nav_report.rs` module docs
- **Invariant:** Redaction is on `Debug`; `Failed.message` / `error_message()` are
  UI diagnostics (callers keep them host-safe)
- **Fix:** Clarify Debug-only redaction wording

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Implement SOCKS reachability probe on `transport_failure` — **forbidden** non-goal; flag recorded, status still Failed immediately |
| REJ-02 | Wire live WebView2 / GPUI / AlwaysAllow COM — **out of scope** |
| REJ-03 | Wire into `wormhole-session` SessionHandle — documented non-goal |
| REJ-04 | Avoid `outcome.clone()` in `navigate_and_report` via `&NavigationOutcome` — micro-opt / API churn, not validated simplify |
| REJ-05 | Add Retry / reconnect API on `HttpNavSession` — not in acceptance criteria |
| REJ-06 | Collapse named cancel/late/disconnect tests into one matrix — attack oracles stay named |
| REJ-07 | Treat ZWSP-only URI as empty — not Unicode White_Space; speculative vs C# |
| REJ-08 | Clear vs keep `error_message` on disconnect C# parity nit — stub clears; status gate is what matters |
| REJ-09 | Purge em dashes for ASCII — crate/docs already use them |

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → tests | HNR-01…05 | Fixed; reset |
| Adv-2 | Reverse: security → lifecycle → docs inventory → Unicode trim | HNR-06, HNR-07 | Fixed; reset |
| Adv-3 | Integration (session/surface unused) → concurrency → security → contract | None | Clean (1/2) |
| Adv-4 | C# line-by-line report/cancel → false-positive tests → docs vs code | None | Clean (2/2) |
| Re-adv-1 | Post-simplify delta: module Debug wording vs `error_message()` | None | Clean (1/2) |
| Re-adv-2 | Redaction + fail-closed + cancel-wait invariants | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Shared validate/apply already central | Pure sync stub | Module “errors never carry” overclaim | Yes → HNR-08; reset | Fixed |
| Sim-2 | Named oracles kept; no missed helpers | Clone of outcome necessary for Fake+session | Docs/tests aligned | None | Clean (1/3) |
| Sim-3 | Same | No I/O / no hot path | No false WebView2 claims | None | Clean (2/3) |
| Sim-4 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

---

## Attack-focus checklist

| Focus | Status |
|---|---|
| Success → Connected (Connecting only) | **Pinned** |
| Fail → Failed + message (Connecting only) | **Pinned** |
| Cancel no-op while Connecting; later success/fail applies | **Pinned** |
| Late reports (incl. cancel) ignored when not Connecting | **Pinned** |
| Empty / whitespace / NBSP URI fail-closed | **Pinned** |
| Cert policy preserved (success / fail / cancel / Fake) | **Pinned** |
| Debug redaction (outcome / session / Fake) | **Pinned** |
| Transport probe / live WebView2 / AlwaysAllow | **Out of scope** (documented) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
```

## Remaining blockers

- Live WebView2 navigation-completed → report wiring and SOCKS transport probe
  remain production/`wormhole-session` / surface-win concerns (**lab ≠ production**).
- No HardwarePass evidence for HTTP tab nav-result on real WebView2 Runtime.
