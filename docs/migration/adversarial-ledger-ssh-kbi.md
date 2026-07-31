# Adversarial ledger — SSH keyboard-interactive multi-prompt Fake channel

**Scope:** `rust/crates/wormhole-ssh/src/kbi.rs` (`FakeKbiChannel` / `NullKbiChannel` / `KeyboardInteractiveChannel` / `answer_kbi_round` / `answer_kbi_rounds` / `KbiInfoRequest` / `KbiRoundResponse` / `KbiPromptError`), KBI exports in `lib.rs`, auth boundary comments + `kbi_fake_channel_does_not_clear_wire_auth_stub` test, KBI section of `docs/migration/06-ssh-spike.md`  
**Out of scope:** Live `authenticate_keyboard_interactive_*` russh wire path; GPUI prompt UI; agent probe / select glue; known_hosts  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope; parent agent; no child agents)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh` — 168 passed + 1 ignored before KBI glue.
- Wire auth already fail-closed: `AuthNotImplemented("keyboard-interactive")` before dial.

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Multi-prompt Fake channel for KBI | **Held** — `KbiInfoRequest` + `Vec<KbiPrompt>`; `answer_kbi_rounds` for multi-round |
| Cancel fail-closed | **Held** — empty script / `NullKbiChannel` / scripted `Cancel` → `KbiPromptError::Cancelled` |
| Debug redacts answers | **Held** — `KbiRoundResponse` / `FakeKbiChannel` use `[REDACTED len=N]`; regressions |
| Document AuthNotImplemented vs stub boundary honestly | **Held** — module docs + `06-ssh-spike.md` table; auth test proves Fake success ≠ wire auth |
| Prefer wormhole-ssh only; unit tests; green suite | **Held** — always-on module; no other crate edits required for the feature |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| SSH-KBI1 | P2 | `kbi` tests | Debug redaction assertion used weak `\|\|` (could pass without `[REDACTED]`) | **Fixed** — require `[REDACTED]` + no plaintext; also check post-consume Debug |
| SSH-KBI2 | P2 | `kbi` tests | Empty `answer_kbi_rounds(&[])`, echo-flag preserve, too-many answers, empty-string answer, unicode redaction unpinned | **Fixed** — focused regressions |
| SSH-KBI3 | P3 | `KeyboardInteractiveChannel` | Trait lacked `Send` (unlike host-key prompt; hurts later task handoff) | **Fixed** — `Send` bound |
| SSH-KBI4 | P2 | `auth` tests | Offline Fake success vs wire `AuthNotImplemented` unpinned together | **Fixed** — `kbi_fake_channel_does_not_clear_wire_auth_stub` |
| SSH-KBIR1 | — | Map `KbiPromptError` → `SshError` | Premature until wire path consumes answers | **Rejected** — keep separate until russh KBI lands |
| SSH-KBIR2 | — | Interior-mutability `&self` channel (Mutex) | `&mut self` matches OTP Fake UI style; no shared owner yet | **Rejected** — churn without caller |
| SSH-KBIR3 | — | Soft-accept wrong answer counts | Would violate fail-closed count contract | **Rejected** |

## Simplify deltas (after adversarial)

- Removed redundant `drop(answers)` on mismatch (scope end drops; length checked first).
- Kept `cancel_all` / `secret` / `visible` helpers for intent clarity (no merge into one constructor).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh --lib kbi
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
cargo check -p wormhole-ssh --no-default-features
```

**Result (final):** default features — green (`cargo test -p wormhole-ssh`; sibling in-tree stubs may add unrelated counts); `--no-default-features` — green. Focused: 16 `kbi::tests` + `auth::tests::kbi_fake_channel_does_not_clear_wire_auth_stub`.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify + `Send` + test hardening).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- Wire KBI auth / GPUI dialog untouched (`AuthNotImplemented` Pending for russh path).
