# Adversarial ledger — WebView2 `cert_policy_to_webview2_behavior`

**Scope:**
- `rust/crates/wormhole-surface-win/src/webview/cert_policy.rs`
- Create-path hook / `WebViewCreateOptions` / `ChildWebViewHost::create` comments (`webview/host.rs`)
- Related notes in `docs/migration/10-http.md`, `docs/migration/native-surface-broker.md`
- Feature-gate wording (`Cargo.toml`, `lib.rs`, `webview/mod.rs`, `webview/env.rs`)

**Out of scope:** Wiring COM `ServerCertificateErrorDetected`; changing default create behavior; C# `WebBrowserView`; full webview host rewrite.

**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-surface-win --features webview --lib` — 85 green  
**Final:** 86 green (added `always_allow_only_from_ignore_errors`)

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after re-adv) |
| `cargo test -p wormhole-surface-win --features webview --lib` | **pass** (86) |
| Default-feature lib tests (no webview) | **pass** (create/default behavior intact) |

---

## Accepted findings

### WVCERT-01 — Crate/Cargo docs implied “AlwaysAllow stub” (`P2`) — **fixed**

- **Where:** `lib.rs` crate docs; `Cargo.toml` `webview` feature comment
- **Invariant:** Adapter is `Default→Default` and `IgnoreErrors→AlwaysAllow` only; no AlwaysAllow without IgnoreErrors
- **Evidence:** Wording ``HttpCertPolicy → AlwaysAllow stub`` read as AlwaysAllow being the stub outcome
- **Impact:** Migration readers / future callers could assume create/lab enables AlwaysAllow
- **Fix:** Explicit bidirectional mapping; “IgnoreErrors → AlwaysAllow only; create/lab leave default validation”
- **Regression:** Doc pin + `always_allow_only_from_ignore_errors`

### WVCERT-02 — Create options lacked explicit “no silent insecure default” contract (`P2`) — **fixed**

- **Where:** `WebViewCreateOptions`, `ChildWebViewHost::create`, create-path hook comment
- **Invariant:** Lab/create must not apply AlwaysAllow; must not use `--ignore-certificate-errors` as a shortcut
- **Evidence:** Hook said “not wired” but options rustdoc did not forbid Chromium cert-ignore args or state the missing `cert_policy` field is intentional
- **Impact:** Future edit could add a silent insecure create default
- **Fix:** Options + `create` rustdoc + hook comment pin: no cert field, leave validate, COM only for IgnoreErrors, never Chromium `--ignore-certificate-errors`
- **Verification:** Create body does not call `cert_policy_to_webview2_behavior(` or subscribe COM

### WVCERT-03 — Docs “lab ≠ production AlwaysAllow” jargon under-specified (`P3`) — **fixed**

- **Where:** `10-http.md`, `native-surface-broker.md`, `webview/mod.rs`, `env.rs`
- **Invariant:** Lab ≠ production must mean AlwaysAllow is **not** applied in lab/create
- **Evidence:** Prior shorthand could be misread; table said “AlwaysAllow stub”
- **Fix:** Spell out Default→validate / IgnoreErrors→AlwaysAllow; “AlwaysAllow not applied in lab/create”
- **Regression:** Ledger + doc review

### WVCERT-04 — Missing negative security pin test (`P2`) — **fixed**

- **Where:** `cert_policy.rs` tests
- **Invariant:** AlwaysAllow reachable only via `IgnoreErrors`; enum/`HttpCertPolicy` defaults stay secure
- **Evidence:** Directional tests existed; no single oracle asserting `Default ≠ AlwaysAllow` + default() chain
- **Fix:** `always_allow_only_from_ignore_errors`
- **Regression:** that test

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Add `cert_policy` field on `WebViewCreateOptions` now — would invite wiring AlwaysAllow into lab create; deferred until production HTTP COM path |
| REJ-02 | `From<HttpCertPolicy>` impl — named function is clearer and harder to misuse silently |
| REJ-03 | Collapse three mapping tests into one — named oracles match attack focus |
| REJ-04 | Deduplicate security wording across host/mod/env/docs into one include — intentional multi-site pins for create vs docs |
| REJ-05 | Claim COM AlwaysAllow wired — **forbidden** by scope; still blocked (lab ≠ production) |
| REJ-06 | Change `args_require_isolated_udf` to error on `--ignore-certificate-errors` — detection for isolation remains useful if a caller wrongly passes it; create docs forbid it |

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → security → integration → docs → tests | WVCERT-01…04 | Fixed; reset |
| Adv-2 | Reverse: security/COM claims → create body → feature tree → mapping inversion | None | Clean (1/2) |
| Adv-3 | Feature gate + COM subscription grep + docs drift + full lib tests | None | Clean (2/2) |
| Re-adv-1 | Post-simplify delta: create rustdoc vs body | None | Clean (1/2) |
| Re-adv-2 | Docs false-wired claims + AlwaysAllow-only pin test | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 (pre re-adv) | Single mapping fn OK | Pure, no I/O | `create` rustdoc pin; comment casing | Yes → reset + re-adv | Fixed |
| Sim-1 (post re-adv) | No missed helpers | No hot-path work | Docs/tests aligned | None | Clean (1/3) |
| Sim-2 | Intentional multi-site pins kept | Same | No false COM claims | None | Clean (2/3) |
| Sim-3 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features webview --lib
```

**Result:** pass (86). Default-feature `--lib` still green (webview/cert_policy gated).

## Remaining blockers

- COM `ServerCertificateErrorDetected → AlwaysAllow` remains **unwired** on
  `ChildWebViewHost::create` / surface-lab (**lab ≠ production**). Pure mapping
  + create-path contract comments only. Production HTTP host must subscribe
  explicitly for `HttpCertPolicy::IgnoreErrors` on an isolated UDF.
