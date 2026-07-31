# Adversarial ledger — HTTP/HTTPS new-window / popup policy Fake glue

**Scope:**
- `rust/crates/wormhole-http/src/new_window.rs`
  (`NewWindowPolicy` / `get_in_session_navigation_uri` / `decide_new_window_policy` /
  `build_bitwarden_popup_uri` / `decide_bitwarden_popup` / `FakeNewWindowSurface`)
- Exports in `wormhole-http` `lib.rs`; Cargo.toml description
- Docs: `docs/migration/10-http.md`, `feature-matrix.md`, `interop-inventory.md`,
  README ledger index

**Out of scope:** Live WebView2 `NewWindowRequested` / GPUI popup hosting;
Bitwarden extension install / storage bridge / active-tab script; changelog
external-link open (`UpdateChangelogView`); `wormhole-session` wiring; C#
`WebBrowserView` / helper edits.

**Authority:** full adversarial-review-fix (edit in scope)  
**Impl:** parent agent (no child agents)  
**Baseline:** `cargo test -p wormhole-http` 72 green (pre-feature)  
**Final:** `wormhole-http` **88** green (**16** `new_window`)

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (Adv-C1/C2) + **2** post-simplify re-adv |
| Iterative-review-simplify clean passes | **3** consecutive (after Sim-1 comment + test rename) |
| `cargo test -p wormhole-http` | **pass** (88) |

---

## Accepted findings

### HNW-01 — Credentialed URI AllowInTab without bases (`P1`) — **fixed**

- **Where:** `get_in_session_navigation_uri` early path (no routed/original bases)
- **Invariant:** Fail closed — never navigate the session tab to a userinfo-bearing
  authority (`https://user:pass@…`)
- **Evidence:** C# returns the raw candidate when bases are null; Fake glue must
  not smuggle credentials into AllowInTab
- **Fix:** `absolute_uri_has_userinfo` gate before AllowInTab; keep `@` reject in
  `split_authority_host_port` for the bases path
- **Regression:** `userinfo_in_authority_fail_closed` (with and without bases)

### HNW-02 — Query-only path rewrite under-pinned (`P2`) — **fixed**

- **Where:** `rewrite_authority` when path is empty but `?query` / `#frag` present
- **Invariant:** C# `UriBuilder` emits `/?…` (leading `/` before query)
- **Fix:** Prefix `/` when `path_query_fragment` starts with `?` or `#`
- **Regression:** `forwarder_rewrites_query_only_path`

### HNW-03 — chrome-extension + forwarder bases HostPopup drift (`P2`) — **fixed**

- **Where:** `decide_new_window_policy` vs `decide_bitwarden_popup` separation
- **Invariant:** Session NewWindow path never returns `HostPopup`; extension URI
  with forwarder bases is unroutable → `Block`
- **Fix:** Extend `session_new_window_never_returns_host_popup`
- **Regression:** that assertion

### HNW-04 — Default HTTP port 80 origin match under-pinned (`P3`) — **fixed**

- **Where:** `default_port` / `same_origin` (HTTPS:443 already pinned)
- **Fix:** `default_http_port_matches_explicit_80`
- **Regression:** that test

### HNW-05 — `ParsedUri` Debug could leak path/query (`P3`) — **fixed** (simplify)

- **Where:** private `ParsedUri` derive
- **Invariant:** Public `NewWindowPolicy` Debug already redacts; private Debug was
  an accidental leak surface
- **Fix:** Drop `Debug` derive on `ParsedUri`

### HNW-06 — Docs / matrix / inventory Pending (`P2`) — **fixed**

- **Where:** `10-http.md`, `feature-matrix.md`, `interop-inventory.md`, README
- **Fix:** Document AllowInTab / HostPopup / Block + Bitwarden HostPopup path;
  mark feature Spike; index this ledger

### HNW-07 — Userinfo rustdoc omission (`P3`) — **fixed**

- **Where:** module table + `get_in_session_navigation_uri` rustdoc
- **Fix:** Name userinfo in Block / `None` conditions

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Live WebView2 / GPUI popup hosting — **forbidden** non-goal |
| REJ-02 | Wire Bitwarden active-tab bridge / extension install — out of scope |
| REJ-03 | Block `javascript:` / `data:` without bases — C# returns candidate; only empty/about:blank/userinfo hardened here |
| REJ-04 | Percent-encoded `..` in Bitwarden path — speculative vs C# `Uri.TryCreate` |
| REJ-05 | Avoid `policy.clone()` in Fake recorder — micro-opt / API churn (same as nav_report REJ) |
| REJ-06 | Add `url` crate — no new deps; thin manual origin parse matches suite style |
| REJ-07 | Changelog `UpdateChangelogView` external open — separate surface, not HTTP session policy |
| REJ-08 | Collapse named forwarder tests into one matrix — attack oracles stay named |

---

## Gate record

### Adversarial loop

| Pass | Attack order | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → security → tests | HNW-01..04, HNW-06 | fixes applied → reset |
| Adv-2 | Security → integration → contract → boundary | HNW-03 extend, HNW-07 | fixes applied → reset |
| Adv-C1 | Boundary → concurrency(N/A) → security → tests | none | clean **1** |
| Adv-C2 | Integration → contract → operability → reuse | none | clean **2** |

### Iterative-review-simplify

| Pass | Reuse / Efficiency / Quality | Accepted | Result |
|---|---|---|---|
| Sim-1 | Drop `ParsedUri` Debug; trim `format_authority` comment; rename userinfo test | HNW-05 | fix → reset |
| Sim-C1 | No further validated simplify | none | clean **1** |
| Sim-C2 | No further validated simplify | none | clean **2** |
| Sim-C3 | No further validated simplify | none | clean **3** |

### Post-simplify re-adversarial

| Pass | Result |
|---|---|
| Re-adv 1 | clean (delta: Debug drop / comment / rename only) |
| Re-adv 2 | clean |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
```

**Result:** 88 passed (16 `new_window`). No commit / push (per task).
