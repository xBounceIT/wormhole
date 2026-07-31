# Adversarial ledger — VNC password-only `auth_glue` stub

**Scope:** `rust/crates/wormhole-vnc/src/auth_glue.rs` (+ docs `09-vnc.md` auth fail-closed table / ledger link, `feature-matrix.md` VNC auth Lab cell, `README.md` index)  
**Authority:** adversarial-review-fix (edit in scope; no live RFB / HardwarePass; no `clipboard_glue` churn; no wormhole-ui/storage/app churn; no git commit/push)  
**Out of scope:** Live RFB challenge/response; CredMgr / GPUI password prompt; MS Logon / VeNCrypt / TLS security types; session negotiate wiring beyond existing `resolve_auth`  
**Baseline (pre-fix):** `cargo test -p wormhole-vnc` **100** passed; uncommitted auth_glue test hardening (provider hard-error + Debug domain pins) already present.

Attack focus:

- Negotiated security → no-auth vs classic VNC password (`select_vnc_auth` / `provide_vnc_auth_input` / `resolve_vnc_auth_from_provider`)
- Username / domain ignored (C# editor hides them for VNC)
- `CredentialsAuthenticationInput` → `UnsupportedCredentialsAuth` (fail-closed; provider not consulted)
- Missing / empty password when VncAuth required → `PasswordRequired`; provider `Ok(None)` → `AuthCancelled`
- `Debug` redacts password on fields / selection / Fake (presence-only for username/domain)
- Fake only — no live VNC

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VNC-AUTH-001 | P2 | `auth_glue` tests | `resolve_vnc_auth_from_provider` cancel/empty fail-closed under-pinned | Convenience wrapper only had happy-path map test | **Fixed** — `resolve_from_provider_fail_closed_on_cancel_and_empty` |
| VNC-AUTH-002 | P3 | tests | Auth error `Display` under-pinned (secrets-adjacent) | PasswordRequired / AuthCancelled / UnsupportedCredentialsAuth | **Fixed** — `auth_errors_display_without_secrets` (+ exact 8-byte provide pin) |
| VNC-AUTH-003 | P3 | `09-vnc.md` | Fail-closed condition/error table + ledger missing (clipboard had one) | Docs accuracy attack lane | **Fixed** — table + ledger link |
| VNC-AUTH-004 | P3 | tests | Empty password + `None` security on `select_vnc_auth` under-pinned | Empty must only fail when VncAuth required | **Fixed** — `select_no_auth_allows_empty_password_and_strips_it` |
| VNC-AUTH-005 | P3 | tests | `VncAuthInputKind::from_security` vs `VncAuthMethod::from_security` alignment unpinned | Drift risk if a new security type is added | **Fixed** — `input_kind_tracks_auth_method_from_security` |
| VNC-AUTH-006 | P3 | `feature-matrix.md` | Lab cell omitted `provide_*` / `AuthCancelled` / ledger link | Integration/docs drift | **Fixed** — Lab cell + ledger link |
| VNC-AUTH-007 | — | C# empty password | C# handler forwards empty string to `PasswordAuthenticationInput` | Rust fail-closed is stronger | **Rejected** — documented Lab contract (`PasswordRequired`) |
| VNC-AUTH-008 | — | `username_ignored` / `domain_ignored` | Always `true` tautology | Intentional parity pin for tests | **Rejected** — keep explicit ignore API |
| VNC-AUTH-009 | — | Zeroize `VncPassword` on Drop | Secret lingering in String | Beyond C# / Lab stub surface | **Rejected** |
| VNC-AUTH-010 | — | Session uses `resolve_auth` not `select_vnc_auth` | Dual path | Session negotiate stays on core `resolve_auth`; glue is provider/fields layer | **Rejected** — out of stated glue scope |
| VNC-AUTH-011 | — | Share Fake Debug / PasswordTooLong through glue | Construction gate is `VncPassword::new` | Glue never builds from raw oversize strings | **Rejected** |

---

## Fixes applied

- Regression tests: provider cancel/empty via `resolve_vnc_auth_from_provider`, Display without secrets, exact 8-byte provide, empty+None select, input-kind/method alignment; call_count on empty provide; prior hard-error + Debug domain pins retained
- `09-vnc.md`: fail-closed table + ledger link
- `feature-matrix.md`: VNC auth Lab cell + ledger link
- Simplify: `VncAuthInputKind::from_security` routes through `VncAuthMethod::from_security`; empty password fail-closed owned solely by `resolve_auth` after cancel `ok_or`
- Ledger + README index entry

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VNC-AUTH-001…003 | Fixed; reset |
| Adv-2 | Reverse: security → integration → docs → boundaries | VNC-AUTH-004…006 | Fixed; reset |
| Adv-3 | Forward: C# parity + exports + fail-closed table + Fake | None (typo hygiene only) | Clean (1/2) |
| Adv-4 | Reverse: exports, error Display, engine feature, PasswordTooLong gate | None (REJ 007–011) | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `from_security` via `VncAuthMethod`; empty via `resolve_auth` only | No extra I/O | Cancel `ok_or` preserved | Yes → reset | Fixed |
| Adv-R* | Post-simplify delta | — | Empty→PasswordRequired; cancel→AuthCancelled | None | See below |
| Sim-2 | Keep explicit ignore pins / Fake ctors | Hot path N/A (Lab Fake) | Tests cover public API | None | Clean (1/3) |
| Sim-3 | Reject `requires_password().then` match rewrite | Same | Diff hygiene: only `auth_glue` in crate | None | Clean (2/3) |
| Sim-4 | Same | Same | No further validated churn | None | Clean (3/3) |

Post-simplify adversarial re-loop:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `ok_or` + `from_security` via method | None | Clean (1/2) |
| Adv-R2 | Security Display + fail-closed table vs simplified provide | None | Clean (2/2) |

No further simplify edits after Adv-R → Sim-2…4 remain the completed simplify gate.

---

## Regression tests (`auth_glue::tests`)

- `resolve_from_provider_fail_closed_on_cancel_and_empty`
- `auth_errors_display_without_secrets`
- `provide_accepts_exact_eight_byte_password`
- `select_no_auth_allows_empty_password_and_strips_it`
- `input_kind_tracks_auth_method_from_security`
- Existing: select no-auth/password/missing/empty, provide happy/cancel/empty/hard-error, Credentials skip provider, None skip provider, resolve map security, Debug redaction (username+domain), input_kind_from_security

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
cargo test -p wormhole-vnc --features engine
```

Result: **pass** — default **105** tests; `--features engine` **106** tests. `git diff --check` clean on in-scope paths. `clipboard_glue` untouched.

## Remaining blockers

- Live RFB challenge/response still deferred (`engine` is presence-only).
- CredMgr / GPUI password prompt UI not wired (Fake provider only).
- C# empty-password forwarding remains weaker than Rust fail-closed (intentional Lab contract).
- Context7 MCP unavailable in this environment; no crate pin change required for this stub.
