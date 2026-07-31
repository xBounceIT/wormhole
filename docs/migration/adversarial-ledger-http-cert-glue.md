# Adversarial ledger — HTTP ignore-cert → WebView2 AlwaysAllow glue

**Scope:**
- `rust/crates/wormhole-surface-win/src/webview/cert_policy.rs`
  (`http_ignore_cert_to_webview2_behavior` / `target_cert_to_webview2_behavior`
  + existing `cert_policy_to_webview2_behavior` contract)
- Create-path honesty (`webview/host.rs`, `webview/env.rs`, `webview/mod.rs`)
- Docs: `docs/migration/10-http.md`, `native-surface-broker.md`, `feature-matrix.md`
- README ledger index row

**Out of scope:** Wiring COM `ServerCertificateErrorDetected`; HardwarePass /
live WebView2 Runtime claims; changing `ChildWebViewHost::create` behavior;
C# `WebBrowserView` edits; `wormhole-domain` inheritance implementation (leaf-only
contract is consumed, not reimplemented here).

**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-http` 40 green;
`cargo test -p wormhole-surface-win --features webview --lib` 98 green  
**Final:** `wormhole-http` 40; surface-win webview lib **104** (cert_policy unit tests **9**, was 6)

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after re-adv) |
| `cargo test -p wormhole-http` | **pass** (40) |
| `cargo test -p wormhole-surface-win --features webview --lib` | **pass** (104) |

---

## Accepted findings

### HCG-01 — Inheritance vs leaf not pinned on glue (`P2`) — **fixed**

- **Where:** `cert_policy.rs` rustdoc + tests
- **Invariant:** Callers pass profile-resolved leaf bool
  (`node.http_ignore_cert_errors.unwrap_or(false)`); folder ignore-cert is
  **not** inherited and must not be OR'd into the glue argument
- **Evidence:** Attack focus required inheritance vs leaf; only scheme×leaf matrix
  existed — no explicit “folder true / leaf unset → false → Default” oracle
- **Impact:** Future callers could walk parents and fail-open AlwaysAllow
- **Fix:** Leaf-only rustdoc; `leaf_glue_treats_unset_as_false_not_folder_inherit`
- **Regression:** that test + docs in `10-http.md` / feature-matrix / broker

### HCG-02 — Scheme-case attack under-pinned (`P2`) — **fixed**

- **Where:** `cert_policy.rs` tests + rustdoc
- **Invariant:** Glue keys off typed `HttpScheme`, not free-form / case-variant
  strings; URI `as_str()` is lowercase `http`/`https`
- **Evidence:** Attack focus “scheme case”; no pin that `"HTTPS"` ≠ enum path
- **Fix:** Document enum-only input; `scheme_is_typed_enum_not_string_case`
- **Regression:** that test

### HCG-03 — Target glue only covered direct builders (`P2`) — **fixed**

- **Where:** `cert_policy.rs` tests
- **Invariant:** Direct / SOCKS / forwarder routing must not change AlwaysAllow
  vs validate for the same scheme×leaf
- **Evidence:** `target_glue_uses_resolved_cert_policy` only used `build_direct_target`
- **Fix:** `target_glue_routing_preserves_fail_closed_matrix` (4×3 builders)
- **Regression:** that test

### HCG-04 — Docs could read “AlwaysAllow applied” / omit leaf-only (`P3`) — **fixed**

- **Where:** `feature-matrix.md`, `10-http.md`, `native-surface-broker.md`
- **Invariant:** Glue is **mapping** only; COM still unwired; leaf-only storage
- **Evidence:** “leaf→AlwaysAllow glue” without **mapping**; broker Cert-ignore
  bullet omitted `target_cert_to_webview2_behavior`
- **Fix:** Wording + leaf-only notes + target helper named; ledger link
- **Regression:** doc review

### HCG-05 — Create-path docs incomplete for leaf/target helpers (`P3`) — **fixed**

- **Where:** `webview/host.rs` `WebViewCreateOptions` / `create` rustdoc
- **Invariant:** Lab create does not call adapter **or** leaf/target glue, and
  does not subscribe COM
- **Evidence:** Options/create mentioned only `cert_policy_to_webview2_behavior`
- **Fix:** Explicit leaf/target + “mapping helpers do not auto-subscribe”
- **Regression:** rustdoc review

### HCG-06 — Non-ASCII rustdoc apostrophes (`P3`) — **fixed**

- **Where:** `cert_policy.rs` leaf/target rustdoc (introduced in HCG-01/03 edits)
- **Invariant:** ASCII rustdoc (parity with prior http-cert simplify)
- **Fix:** Replace curly apostrophes with ASCII `'`

### HCG-07 — `env.rs` omitted target glue (`P3`) — **fixed** (simplify)

- **Where:** `webview/env.rs` module docs
- **Invariant:** Isolation docs name the same leaf/target helpers as `mod.rs`
- **Fix:** Mention `target_cert_to_webview2_behavior` alongside leaf glue

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Re-gate `target_cert_to_webview2_behavior` by parsing navigate URI scheme — C# trusts resolved `IgnoreCertErrors`; builders / `resolve_cert_policy` are the gate (same as HCERT REJ-01) |
| REJ-02 | Wire COM AlwaysAllow in create/lab — **forbidden** by scope; still blocked |
| REJ-03 | Claim HardwarePass / live WebView2 Runtime for cert path — **forbidden** |
| REJ-04 | Collapse named fail-closed / inheritance / scheme tests into one matrix — attack oracles stay named |
| REJ-05 | Depend on `wormhole-domain` from surface-win to call InheritanceResolver in glue tests — wrong layer; glue consumes bool |
| REJ-06 | Hoist test imports / micro-dedupe double calls — taste, not validated simplify |

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → security → inheritance/scheme attacks → integration → docs → tests | HCG-01…05 | Fixed; reset |
| Adv-2 | Reverse: COM claims → create body grep → ASCII → docs target naming | HCG-05 (create), HCG-06, docs target bullet | Fixed; reset |
| Adv-3 | C# parity + attack-focus checklist + COM subscribe grep | None | Clean (1/2) |
| Adv-4 | Integration drift (exports, feature-matrix Lab, no HardwarePass) | None | Clean (2/2) |
| Re-adv-1 | Post-simplify delta: `env.rs` leaf/target wording | None | Clean (1/2) |
| Re-adv-2 | False-wired claims + AlwaysAllow-only + fail-closed matrix | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 (pre re-adv) | Helpers already chain resolve→adapter | Pure, no I/O | `env.rs` missing target glue | Yes → reset + re-adv | Fixed HCG-07 |
| Sim-1 (post re-adv) | No missed helpers | No hot-path work | Docs/tests aligned | None | Clean (1/3) |
| Sim-2 | Intentional multi-site pins kept | Same | No false COM claims | None | Clean (2/3) |
| Sim-3 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

---

## Attack-focus checklist

| Focus | Status |
|---|---|
| HTTP + ignore true → never AlwaysAllow | **Pinned** (`leaf_glue_fail_closed`, routing matrix) |
| HTTPS + false → validate | **Pinned** (same) |
| Inheritance vs leaf (folder true / leaf unset) | **Pinned** (`leaf_glue_treats_unset_as_false_not_folder_inherit`) |
| Scheme case (typed enum / lowercase `as_str`) | **Pinned** (`scheme_is_typed_enum_not_string_case`) |
| COM still unwired (no lab AlwaysAllow apply) | **Pinned** (create rustdoc + body; no `add_ServerCertificate*`) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
cargo test -p wormhole-surface-win --features webview --lib
```

## Remaining blockers

- COM `ServerCertificateErrorDetected → AlwaysAllow` remains **unwired** on
  `ChildWebViewHost::create` / surface-lab (**lab ≠ production**). Pure mapping
  + leaf/target glue + create-path contract comments only. Production HTTP host
  must subscribe explicitly for `HttpCertPolicy::IgnoreErrors` on an isolated UDF.
- No HardwarePass evidence for live WebView2 cert-error handling.
