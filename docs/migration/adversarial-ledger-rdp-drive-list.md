# Adversarial ledger — RDP drive-list glue (`DriveCollection` parity)

**Scope:** `rust/crates/wormhole-surface-win/src/rdp/drive_list.rs` (new: `parse_drive_letters` / `validate_drive_list` / `normalise_drive_list` / `DriveLetters` / `RdpDriveListError`) + `rdp/mod.rs` registration/re-exports + thin adapter `parse_redirect_drives_canonical` in `display_redirect_glue.rs` (closed `parse_redirect_drives`/`apply_from_profile` untouched).

**Out of scope:** live `MsRdpClient` `DriveCollection` COM enumeration (pending); other surface-win modules.

**Compared against:** C# `Helpers/RdpDriveList.cs` — `ParseLetters`/`Validate`/`Normalise`; `Validate` counts **UTF-16 units** (`p.Length`), not Rust scalars. Verified against a real .NET 10 runtime run across 43 hostile inputs.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-surface-win **95** tests (**234** with `--features rdp`)  
**Final:** wormhole-surface-win **98** tests (**237** with `--features rdp`)

**Attack focus:** UTF-16 vs scalar length (`😀` must be "not a single drive letter"), `" all "` padded sentinel, tab/NBSP non-separators, dedupe/order (NOT sorted — C# preserves order), Unicode case-mapping divergence (`ſ`→`S` sole sanctioned deviation), Debug leakage, closed-glue adapter regression.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (incl. .NET 10 oracle run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-surface-win` | **pass** (98) |
| `cargo test -p wormhole-surface-win --features rdp` | **pass** (237) |
| `cargo check` / `clippy --features rdp` | **pass** / no new warnings |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F1 | P2 | `validate_drive_list` counted Rust scalars; C# counts UTF-16 units (`"😀".Length == 2`) → wrong message for astral chars | `token.encode_utf16().count() != 1`; `validate_astral_char_is_not_single_letter_like_csharp` |
| F2 | P3 | Module doc table mislabeled `"C,12"`/`"cf"` result | Corrected |
| F3 | P3 | Padded `" all "` in Validate, tab/NBSP non-separators, internal whitespace unpinned | 3 tests pinned |
| F4 | P3 | Clippy `manual_pattern_char_comparison` | `split([',', ';', ' '])` |

### Rejected candidates

Unicode case-mapping divergence (`ı`/`ſ`/`K`) — sanctioned fail-closed ASCII-only rule (only `ſ`→`S` differs; documented); `REDIRECT_DRIVES_ALL` literal duplication (closed glue untouched); `parse_strict` double-pass.

---

## Test command

```powershell
cd rust
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
```

**Counts:** `rdp::drive_list` **14+** + adapter parity test; full wormhole-surface-win **98** (237 with rdp).