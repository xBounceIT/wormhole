# Adversarial ledger — terminal font / size / auto-copy settings apply glue

**Scope:**
- `rust/crates/wormhole-terminal/src/settings_apply.rs`
  (`TerminalSettingsConfig` / `AppliedTerminalSettings` /
  `FakeTerminalSettingsSurface` / `accept_selection_auto_copy`)
- `rust/crates/wormhole-ui/src/settings/terminal_apply.rs`
  (`terminal_settings_config_from_app` / `apply_terminal_settings_*`)
- `wormhole-ui` `AppSettings` default helpers → `DEFAULT_SSH_FONT_*`
- Docs: `14-terminal-bridge.md`, `17-tree-settings-vm.md`, `feature-matrix.md`,
  README ledger index

**Out of scope:** Live WebView2 / xterm `term.options` / `ExecuteScript` push;
`d:`/`c:` codec pump; GPUI settings chrome; C# `TerminalBridge` / `bridge.js`
edits; paste / auto-sudo paths.

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Impl:** parent agent  
**Baseline:** `settings_apply` 9 + `terminal_apply` 5 green (pre-review)  
**Final:** `settings_apply` **10** + `terminal_apply` **5** green

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (Adv-2/3) + **2** post-simplify re-adv (Adv-R1/R2) |
| Iterative-review-simplify clean passes | **3** consecutive (after Sim-fix batch) |
| `cargo test -p wormhole-terminal --lib settings_apply` | **pass** (10) |
| `cargo test -p wormhole-ui --lib settings::terminal_apply` | **pass** (5) |

---

## Accepted findings

### TSA-01 — Auto-copy gate omitted `MAX_SELECTION_UTF8_BYTES` (`P2`) — **fixed**

- **Where:** `accept_selection_auto_copy` / Fake `try_auto_copy_selection`
- **Invariant:** C# `TerminalBridge` ignores decoded selections larger than
  `MaximumSelectionUtf8Bytes` (4 MiB)
- **Evidence:** Lab accepted any non-empty payload when auto-copy was on
- **Fix:** Gate `selection_utf8.len() <= MAX_SELECTION_UTF8_BYTES`
- **Regression:** `auto_copy_gate_matches_csharp_c_frame_policy`,
  `fake_auto_copy_records_length_only_never_body`

### TSA-02 — NBSP / Unicode White_Space empty font under-pinned (`P2`) — **fixed**

- **Where:** `validate_terminal_settings` / UI mapper tests
- **Invariant:** Fail-closed empty includes `str::trim` White_Space (NBSP)
- **Fix:** NBSP cases in terminal + UI fail-closed tests; trim-with-content pin
- **Regression:** `empty_and_whitespace_font_fail_closed`,
  `empty_font_from_app_fail_closed`, `trims_font_family_on_success`

### TSA-03 — UI `AppSettings` defaults drifted from terminal constants (`P2`) — **fixed**

- **Where:** `wormhole-ui` `settings/model.rs` `default_ssh_font*`
- **Invariant:** AppSettings defaults must match `TerminalSettingsConfig::default`
  / C# `Cascadia Mono` / 12
- **Fix:** Defaults use `DEFAULT_SSH_FONT_FAMILY` / `DEFAULT_SSH_FONT_SIZE`
- **Regression:** `default_app_settings_apply_to_fake` parity asserts

### TSA-04 — Awkward fail-path match in UI test (`P3`) — **fixed** (simplify)

- **Where:** `terminal_apply` `non_positive_size_from_app_fail_closed`
- **Fix:** `unwrap_err()`

### TSA-05 — `FakeTerminalSettingsSurface::clear` unpinned (`P3`) — **fixed** (simplify)

- **Where:** Fake `clear`
- **Fix:** `fake_clear_resets_snapshot_messages_and_auto_copy`

### TSA-06 — Docs / matrix omitted NBSP + oversize auto-copy (`P3`) — **fixed**

- **Where:** `14-terminal-bridge.md`, `17-tree-settings-vm.md`,
  `feature-matrix.md`, module rustdocs
- **Fix:** Document Unicode trim + `MAX_SELECTION_UTF8_BYTES` skip

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Live xterm `term.options` / WebView2 push — **forbidden** non-goal; Fake only |
| REJ-02 | Upper-bound font size (`i32::MAX`) — C# has no cap; speculative |
| REJ-03 | Reject ZWSP-only font — not Unicode White_Space; C# `IsNullOrWhiteSpace` parity |
| REJ-04 | Replace Fake message append with replace-on-reapply — intentional audit trail |
| REJ-05 | Share whitespace helpers across crates — micro-dupe; local `trim` fine |
| REJ-06 | Avoid 4 MiB test allocations — needed to pin size limit; cheap in practice |
| REJ-07 | Wire font apply into settings VM setters — out of scope (mapper + Fake only) |

---

## Gate record

### Adversarial loop

| Pass | Focus | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract / boundary / security / C# auto-copy / defaults | TSA-01..03, 06 | Fixed; reset |
| Adv-2 | Reverse: tests→security→concurrency→state→docs | None | Clean (1/2) |
| Adv-3 | Lifecycle clear; Debug redaction; ZWSP/upper-bound sweep | None (rejected) | Clean (2/2) |
| Adv-R1 | Post-simplify delta (clear test / unwrap_err / docs / NBSP trim) | None | Clean (1/2) |
| Adv-R2 | Reverse: public mapper fail-closed; defaults parity; oversize gate | None | Clean (2/2) |

### Iterative-review-simplify

| Pass | Reuse | Efficiency | Quality | Result |
|---|---|---|---|---|
| Sim-fix | Shared `DEFAULT_SSH_FONT_*` (from TSA-03) | — | unwrap_err; clear test; docs/matrix; NBSP trim pin | Fixed; reset |
| Sim-1 | Defaults shared; thin UI mapper | No hot-path I/O | Fail-closed + Debug lengths-only | Clean (1/3) |
| Sim-2 | Keep layering (ui mapper ≠ terminal core) | Reject Cow micro-opt | Error Display body-free | Clean (2/3) |
| Sim-3 | Reject cross-crate whitespace helper | Message append intentional | Docs aligned with code | Clean (3/3) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo test -p wormhole-terminal --lib settings_apply
cargo test -p wormhole-ui --lib settings::terminal_apply
git diff --check -- rust/crates/wormhole-terminal/src/settings_apply.rs rust/crates/wormhole-ui/src/settings/terminal_apply.rs rust/crates/wormhole-ui/src/settings/model.rs docs/migration/adversarial-ledger-terminal-settings-apply.md
```

Result: **pass** — 10 + 5 focused unit tests. Diff hygiene clean for touched paths.
