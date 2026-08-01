# Adversarial ledger — Credential binding service UI glue

**Scope:** `rust/crates/wormhole-ui/src/credential_binding.rs` (new) + `mod`/`pub use` block in `src/lib.rs`.

**Out of scope:** GPUI/WinUI binding chrome; `wormhole-domain` inheritance resolver internals (read-only); QC ephemeral credentials.

**Compared against:** C# `Services/ConnectionCredentialBindingService.cs`, `Models/CredentialBindingMode.cs`, `ConnectionEditorViewModel` (`EffectiveCredentialMode`/`WriteTo`), `NewConnectionDialog.xaml.cs` (`CommitCredential`), `CredentialPickerSearch` (`Matches` = name/username/domain), `FolderEditorViewModel`, `InheritanceResolver`.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified final battery)  
**Baseline:** wormhole-ui lib **471** tests  
**Final:** wormhole-ui lib **478** tests (+ 17 doc + 5 integration)

**Attack focus:** state-machine transitions (Inherit/None/Saved), inline-password exclusivity vs `connection_editor`, commit-key resolution (name/username/domain + sentinel exclusion + no-match revert), legacy null+CredentialId shapes, `OrdinalIgnoreCase` parity, Debug leakage.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui` | **pass** (478 + 17 + 5) |
| `cargo check -p wormhole-ui` | **pass** (1 pre-existing warning) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| P2 | Commit substring pass matched name only (C# matches name/username/domain) | Reuse `profile_matches_query` |
| P2 | Exact-name pass could return a sentinel row id → `Saved`+invalid state | Sentinels excluded in both passes (commit path is saved-credentials-only) |
| P2 | `select_credential_by_commit_key` cleared to `None` on no-match text (C# `CommitCredential` reverts, keeps selection) | No-match keeps current selection; only empty/whitespace clears |
| P3 | Dead code `ParentBindingContext::is_present` | Removed |
| P3 | `eq_ignore_ascii_case` vs C# `OrdinalIgnoreCase` | Lowercase (Unicode-aware) equality |
| P3 | Legacy inline-node load footgun + legacy-sentinel behavior unpinned | `from_legacy` doc + regression tests |

### Simplify delta

Reused `profile_matches_query`; renamed typo'd test; domain test row got its own id.

### Rejected candidates

Empty-commit → `None` vs C# `Inherit` (documented safer divergence); `select_credential(Some(sentinel))` fail-closed rejection; cross-module legacy-mode duplication (independent state machines).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-ui credential_binding
cargo test -p wormhole-ui
```

**Counts:** credential_binding **35** tests; full wormhole-ui lib **478**.