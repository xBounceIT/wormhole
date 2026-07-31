# Adversarial ledger — SFTP transfer conflict overlay policy

**Scope:** `rust/crates/wormhole-sftp/src/conflict.rs` (`resolve_conflict_overlay`, `apply_conflict_choice`, `suggest_rename_name`, `ConflictDecision` / `ConflictContext` / `ConflictChoice` / `ConflictOutcome` / `FakeConflictOverlay`), `lib.rs` re-exports, `docs/migration/11-sftp.md` conflict section, feature-matrix SFTP overlay row, README ledger link  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no GPUI overlay chrome; no orchestrator flatten/transfer apply wiring)  
**Preserved:** `is_safe_remote_name` rejection, transfer queue cancel / single-flight, dialog open fail-closed, progress size-only snapshots  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp` green (66 lib + 12 serialize); conflict module absent  
**Compared against:** C# `ConflictDecision` / `ConflictContext` / `ConflictResolver`, `FileTransferOrchestrator` sticky `ApplyToAll`, `FileTransferDialog` overlay (Overwrite / Skip / Cancel→Skip without apply-all)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| CONF-01 | P2 | `resolve_conflict_overlay` sticky arm | Public `sticky: &mut Option<ConflictDecision>` can hold Rename/Cancel; silent apply would violate `may_stick` | Clear foreign sticky then prompt; pin with test | `foreign_sticky_cleared_then_prompts` |
| CONF-02 | P2 | `conflict::tests` | Suggest helper + missing-dest + directory-flag interaction thin | `rename_via_suggest_helper`, `missing_destination_ignores_directory_flag` | those tests |
| CONF-03 | P3 | `11-sftp.md` / feature-matrix / README | Conflict policy Lab note + ledger link missing | Doc section + matrix Lab note + README row | docs review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | sticky match | Use `decision.may_stick()` guard instead of duplicating Skip\|Overwrite pattern | full `wormhole-sftp` suite; adversarial re-looped to 2 clean |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Collapse Lab `Cancel` into C# Skip-without-apply-all | User deliverable requires distinct Cancel; docs call out the C# mapping |
| Fail closed on whitespace-padded (non-empty-after-trim) paths | Speculative; EmptyPath is trim-empty only (matches dialog blank rule) |
| Wire `resolve_conflict_overlay` into `TransferQueue` / dialog `start_transfer` | Documented host / follow-up; this stub is policy + Fake only |
| Sticky Rename with auto-increment per file | Unique leaf names need host UX; InvalidSticky rejects apply-to-all Rename |
| Soften `ExistingDirectory` to Skip | Fail closed matches “dirs are not file conflict prompts”; C# never builds this context for files |
| `#[derive(Debug)]` on `ConflictContext` | Hand Debug keeps the credential-free field whitelist explicit (dialog/progress parity) |
| Allow Overwrite when `existing_is_directory` | Would clobber remote directories; refuse |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation (S-01).

### Clean pass 1 — order: contract → boundaries → state → security → tests

- Exists → Skip/Overwrite/Rename/Cancel; missing → Proceed; empty paths / dir-at-dest / bad rename / InvalidSticky / PromptExhausted fail closed.
- Sticky Skip/Overwrite suppress prompts; Cancel clears sticky; foreign sticky cleared then prompts.
- No credential fields; errors / Debug omit password-shaped text (pinned).
- **Accepted findings:** none.

### Clean pass 2 — order: integration → concurrency → operability → boundaries → contract

- `lib.rs` re-exports; `11-sftp.md` + feature-matrix Lab note match Fake/policy contracts; Rename Lab-forward vs WinUI buttons documented.
- Pure sync policy (no async races); Fake script is single-threaded `&mut`.
- Suggest helper + safe-name gate; directory flag ignored when destination missing.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-established after S-01).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Quality (sticky Skip\|Overwrite duplicated `may_stick`) | S-01 applied → adversarial re-looped to 2 clean; simplify counter reset |
| 1 (clean) | Reuse (keep policy separate from queue/dialog); efficiency (no I/O); quality (retain hand Debug / fail-closed dir) | Clean |
| 2 | Reject Cancel→Skip collapse / padded-path strictness / queue wiring / sticky Rename | Clean |
| 3 | Docs/matrix parity; Fake exhaust records prompt attempt; no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
```

**Result:** green — 82 lib + 12 `serialize_queue` (94 total). Conflict module: 16 unit tests.

**Diff hygiene:** scoped to `wormhole-sftp` conflict glue + migration docs (`11-sftp.md`, feature-matrix, README, this ledger). No commit/push (per parent).
