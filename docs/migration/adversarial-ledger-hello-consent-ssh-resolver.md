# Adversarial ledger — Hello consent + SSH password resolver glue

**Scope:** `rust/crates/wormhole-secrets-win/src/hello_consent.rs` (new), `src/ssh_password_resolver.rs` (new), `src/lib.rs` registration/re-exports.

**Out of scope:** WinRT user-verification I/O; real `bw` spawn; `CredentialPasswordResolverGlue` (closed ledger `adversarial-ledger-credential-resolve.md`).

**Compared against:** C# `Services/Security/*` Hello availability/consent/remote-session (`SM_REMOTESESSION`), `Services/Ssh/SshCredentialResolver.cs` (inline→saved→Bitwarden order; locked-vault unlock; `BitwardenItemId` checked before the session gate).

**Authority:** full adversarial-review-fix (reviewer subagent; parent fixed a pre-existing test compile error + 2 broken tests during the wave, then re-verified)  
**Baseline:** wormhole-secrets-win **269** tests  
**Final:** wormhole-secrets-win **275** tests

**Attack focus:** secret leakage through derived `Debug` (`UnlockPromptResponse::Submitted{master}`, `FakeUnlockPromptScript::Submit`, freeform `HelloConsentResult.message`), unlock retry logic, C# ordering (item-ref before session gate), channel drop/abandon, availability/remote/UI fail-closed matrix, `SshPasswordValue` expose-only.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (275) |
| `cargo check -p wormhole-secrets-win` | **pass**, no warnings |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| P2 | `UnlockPromptResponse` derived Debug printed the secret `master` | Manual `Debug` → `Submitted([REDACTED])` |
| P3 | `FakeUnlockPromptScript` Debug echoed test-dummy master | Manual redaction |
| P3 | `HelloConsentResult` Debug exposed freeform `message` | `granted` + `message_len` only |
| P3 | `PendingUnlockPrompt` doc claimed drop → failure; impl → Canceled | Doc aligned with impl + C# |
| P3 | `read_bitwarden_password` ran the session gate before item-ref checks → spurious unlock prompt on missing ref | Reordered item-id/field-path checks before the session gate (C# `CredentialPasswordResolver.cs:47-53`) |
| P3 | Unused `TestGlue` alias (build warning) | Removed |

### Regression tests (6)

`result_debug_never_exposes_freeform_message`, `unlock_response_and_script_debug_never_echo_master`, `unlock_claims_success_but_session_still_locked_errors`, `unlock_channel_receiver_dropped_fails_closed`, `missing_item_ref_never_prompts_unlock`, `bitwarden_provider_never_reads_local_store`.

### Rejected candidates

Concurrent-unlock-prompt serialization (C# `_unlockGate` parity — reference glue doesn't gate); `ensure_non_empty` duplication (read-only reference); blocking `recv()` without timeout (documented design).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-secrets-win hello_consent ssh_password_resolver
cargo test -p wormhole-secrets-win
```

**Counts:** full wormhole-secrets-win **275** (incl. hello_consent + ssh_password_resolver suites).