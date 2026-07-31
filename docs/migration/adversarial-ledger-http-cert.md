# Adversarial ledger — `HttpCertPolicy` (`wormhole-http`)

**Scope:** `rust/crates/wormhole-http/` (`HttpCertPolicy`, `resolve_cert_policy`, `effective_ignore_cert`, `HttpConnectionTarget.cert_policy`, builders), `docs/migration/10-http.md`  
**Out of scope:** WebView2 host / AlwaysAllow subscription (`wormhole-surface-win`)  
**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-http` — 31 tests green before review  
**Final:** 33 tests green  

Compared against C#: `HttpSessionViewModel.BuildTargetAsync`  
(`ignoreCert = Protocol == Https && HttpIgnoreCertErrors`).

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-http` | **pass** (33) |

---

## Accepted findings

### HCERT-01 — Docs/rustdoc risked implying AlwaysAllow was wired (`P2`) — **fixed**

- **Where:** `docs/migration/10-http.md`, `target.rs` rustdoc on `HttpCertPolicy` / `ignores_errors`
- **Invariant:** Docs must not claim WebView2 `AlwaysAllow` is wired in Rust UI / this crate
- **Evidence:** Prior wording (“view should subscribe AlwaysAllow”) read as current host behavior; crate only resolves policy
- **Impact:** Migration readers could assume cert-error bypass already works in Rust surfaces
- **Fix:** Explicit “not wired here / not in Rust UI; future `wormhole-surface-win` host”
- **Regression:** Doc review in ledger; wording pinned in `10-http.md` cert-policy section

### HCERT-02 — Public ungated `from_ignore_flag(bool)` → `IgnoreErrors` (`P2`) — **fixed**

- **Where:** `HttpCertPolicy::from_ignore_flag`
- **Invariant:** Leaf → policy must be HTTPS ∧ `HttpIgnoreCertErrors` only (`resolve_cert_policy`)
- **Evidence:** Public helper mapped raw leaf `true` to `IgnoreErrors` with no scheme gate
- **Impact:** Callers could bypass C# `BuildTargetAsync` gating
- **Fix:** Removed helper; `resolve_cert_policy` inlines HTTPS ∧ leaf → enum (only public leaf→policy path)
- **Regression:** `cert_policy_helpers`, `scheme_flag_matrix_all_builders`

### HCERT-03 — No Debug secret-contract regression (`P2`) — **fixed**

- **Where:** `HttpConnectionTarget` / `HttpCertPolicy` derived `Debug`
- **Invariant:** No secrets in Debug (targets are credential-less)
- **Evidence:** Attack focus required a pin; fields were safe but untested
- **Fix:** `target_debug_has_no_secrets` asserts URI/policy present and bans password/token/cookie/etc. substrings
- **Regression:** `target_debug_has_no_secrets`

### HCERT-04 — Scheme × leaf × builder matrix under-pinned (`P3`) — **fixed**

- **Where:** tests for direct / SOCKS / forwarder policy preservation
- **Invariant:** HTTP + leaf true never `IgnoreErrors`; SOCKS/forwarder preserve resolved policy
- **Evidence:** Named tests covered cases; no single exhaustive matrix oracle
- **Fix:** `scheme_flag_matrix_all_builders` (4 scheme/flag combos × 3 builders + `resolve_cert_policy`)
- **Regression:** `scheme_flag_matrix_all_builders`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | `HttpConnectionTarget::new` can take `IgnoreErrors` with `http://` URI — matches C# record; gating lives on builders / `resolve_cert_policy` |
| REJ-02 | — | Extract shared “validate + resolve + navigate” helper across three builders — would obscure distinct routing shapes |
| REJ-03 | — | Bitwarden `ignore_certificate_errors: bool` profile fingerprint — separate HTTPS-gated API; not `HttpCertPolicy` leaf resolution |
| REJ-04 | — | Type-system forbid `IgnoreErrors` on HTTP navigate URI — over-constraint vs C#; builders are the contract |
| REJ-05 | — | Custom `Debug` impl (vs derived) — no secret fields; derived + regression sufficient |

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | HCERT-01…04 | Fixed; reset |
| Adv-2 | Reverse: Debug/PII → AlwaysAllow claims → scheme gate → builders → session integration | None | Clean (1/2) |
| Adv-3 | C# `BuildTargetAsync` parity oracle → attack-focus checklist → test resistance | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Drop redundant `from_ignore_flag` (inlined) | N/A | ASCII rustdoc quotes; tighten Debug asserts | Yes → reset | Fixed |
| Sim-2 | No missed helpers worth extracting | No hot-path I/O | No further validated issues | None | Clean (1/3) |
| Sim-3 | Same | Same | Docs/API/tests aligned | None | Clean (2/3) |
| Sim-4 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

Simplify changed implementation → adversarial re-run on delta:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: inlined `resolve_cert_policy`, public leaf→policy surface | None | Clean (1/2) |
| Adv-R2 | Reverse: security/docs/builders on post-simplify surface | None | Clean (2/2) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
```

Result: **pass** — 33 unit tests.

Attack-focus checklist:

| Focus | Status |
|---|---|
| HTTP never `IgnoreErrors` even if leaf true | **Pinned** (`plain_http_never_ignores_cert`, matrix) |
| HTTPS ∧ `HttpIgnoreCertErrors` only | **Pinned** (`resolve_cert_policy`) |
| SOCKS/forwarder builders preserve policy | **Pinned** (matrix + named socks/forwarder tests) |
| No secrets in Debug | **Pinned** (`target_debug_has_no_secrets`) |
| Docs do not claim AlwaysAllow wired in Rust UI | **Pinned** (`10-http.md` + rustdoc) |

## Remaining blockers

- WebView2 `ServerCertificateErrorDetected → AlwaysAllow` COM subscription is still
  future work on the production HTTP host. `wormhole-surface-win` now has the pure
  `cert_policy_to_webview2_behavior` adapter (+ create-path hook comment); surface-lab
  still leaves default validation (**lab ≠ production AlwaysAllow**).
