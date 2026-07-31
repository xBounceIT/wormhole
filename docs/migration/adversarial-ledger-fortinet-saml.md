# Adversarial ledger — Fortinet SamlAuthFlow stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/fortinet/saml.rs` (+ exports in `fortinet/mod.rs` / `providers/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` SAML notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** wire into `FortinetProvider::establish` unless security requires)  
**Baseline:** `cargo test -p wormhole-tunnels` green before / after review  
**Compared against:** C# `IFortinetSamlAuthService` / `FortinetSamlAuthResult` / `FortinetSettings.DefaultSamlRedirectPort` (= **8020**)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (167 lib + 15 lease + 24 sidecar) |

---

## Accepted findings

### SAML-01 — Embedded↔External mismatch fail-closed under-pinned (`P2`) — **fixed**

- **Where:** `authenticate` / `matches_flow` tests
- **Invariant:** External must yield `auth_id`; Embedded must yield `SVPNCOOKIE`; mismatch → `InvalidResult` (no secret echo)
- **Evidence:** Only External+cookie mismatch was tested; Embedded+AuthId path unpinned
- **Fix:** Extended `authenticate_rejects_mismatched_credential_kind` for both directions
- **Regression:** that test

### SAML-02 — Empty / whitespace `SVPNCOOKIE` under-pinned (`P2`) — **fixed**

- **Where:** `authenticate` + `has_exactly_one_credential`
- **Invariant:** empty / whitespace-only tokens → `InvalidResult` for both credential kinds
- **Evidence:** whitespace AuthId covered; cookie whitespace / empty lacked regressions
- **Fix:** Extended `authenticate_rejects_empty_token`
- **Regression:** that test

### SAML-03 — Module docs read as live WebView2 / OS-browser (`P2`) — **fixed**

- **Where:** `saml.rs` module / `SamlAuthFlow` docs; `07-tunnels-mcp.md` OTP/SAML wording
- **Invariant:** Docs must **not** claim WebView2 or external-browser UI are implemented
- **Evidence:** Bullets described OS browser / WebView2 paths without “intended / UI later”; OTP section said “SAML / Entra WebView2 remain TODO” ambiguously
- **Fix:** Module docs mark paths as intended shapes; enum docs say no launch / no WebView2; OTP bullet clarifies interactive **UI** TODO + points at SAML stub
- **Regression:** doc review + existing stub `NotImplemented` wording

### SAML-04 — `FakeSamlAuthCallback` Debug echoed `Failed` payloads (`P2`) — **fixed**

- **Where:** `FakeSamlAuthCallback` `Debug`
- **Invariant:** `auth_id` / `SVPNCOOKIE` (and accidental secret-bearing error strings) never appear in Debug
- **Evidence:** `Err(e)` used `Debug` of `SamlAuthError::Failed(msg)` verbatim
- **Fix:** Redact `Failed(_)` as `Err(Failed([REDACTED]))`
- **Regression:** `fake_debug_redacts_failed_payload`

### SAML-05 — `authenticate` cloned the full request (`P3`) — **fixed** (simplify)

- **Where:** `authenticate`
- **Fix:** Capture `flow` (Copy) then `callback.complete(request)` by move — no `config_name` clone

### SAML-06 — Misleading `has_exactly_one_credential` doc (`P3`) — **fixed** (simplify)

- **Where:** `SamlAuthResult::has_exactly_one_credential`
- **Evidence:** Comment claimed constructors reject empty; only `authenticate` does
- **Fix:** Corrected doc comment

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire SAML into `FortinetProvider::establish` — explicitly out of scope (sidecar path unchanged) |
| REJ-02 | — | Realm + external SSO / cert-pin + embedded rejects — live in C# `FortinetTunnelProvider`, not this stub |
| REJ-03 | — | `MaxAuthIdLength` (4096) parse — belongs to future loopback listener / protocol, not path stub |
| REJ-04 | — | Zeroize credential bytes on `Drop` — hardening beyond C# / stub surface |
| REJ-05 | — | Custom `Debug` on `SamlAuthError::Failed` always — diagnostics need the (secret-free) message; Fake Debug already redacts |
| REJ-06 | — | Macro-merge `SamlAuthId` / `SvpnCookie` Debug/Display — two types match OTP/Entra pattern; not worth churn |
| REJ-07 | — | Constructor reject of empty tokens — C# `FromAuthId` / `FromSvpnCookie` also defer to `HasExactlyOneCredential` |

---

## Adversarial cycles

1. **Cycle 1 (findings):** SAML-01 / SAML-02 / SAML-03 / SAML-04 accepted → mismatch + empty-cookie tests, module/doc wording, Fake Failed redaction → reset  
2. **Cycle 2 (findings):** OTP-section UI wording (part of SAML-03) + move-not-clone (SAML-05) → reset  
3. **Clean pass 1:** Security → boundaries → contract (redaction, port 0, Stub `NotImplemented`, docs non-claim, establish unwired) — no accepted findings  
4. **Clean pass 2:** Integration / concurrency / test resistance (exports, Fake mutex, both mismatch directions pinned) — REJ-01..07 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on move-not-clone + doc-comment delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** efficiency (move request; SAML-05); quality (credential doc; SAML-06)  
2. **Clean pass 1:** reuse (`redact_nonempty`) / efficiency / quality — no validated findings  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::fortinet::saml::`

---

## Residual / out-of-scope notes

- `StubSamlAuthCallback` remains the fail-closed production default until WebView2 / OS-browser UI lands.
- `FortinetProvider::establish` still takes already-resolved sidecar JSON; SAML material is not obtained inside establish.
- Concurrent workspace churn touched `providers/cisco/` (module layout); SAML review did not change Fortinet sidecar establish behavior.
