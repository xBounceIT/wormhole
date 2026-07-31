# Adversarial ledger — Bitwarden browser extension manual ZIP/folder install pin (`wormhole-secrets-win`)

**Scope:**
- `rust/crates/wormhole-secrets-win/src/bitwarden_extension_install.rs`
- Path helpers reused from `paths.rs` (`bitwarden_extension_root`, `bitwarden_extension_install_dir`, `ensure_confined_under`)
- Crate-root re-exports in `lib.rs` / `Cargo.toml` description
- Docs: `04-secrets.md`, `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# `BitwardenBrowserExtensionInstaller` HTTP download / GitHub release resolution;
live `zip` crate extraction on disk; WebView2 extension host / cookie seeding (`wormhole-http`);
`BitwardenBrowserExtensionUpdateService` stale-check scheduler; GPUI settings chrome.

**Compared against:** C# `BitwardenBrowserExtensionInstaller` + `BitwardenBrowserExtensionInstallerTests` +
`BitwardenBrowserExtensionUpdateServiceTests` (manual/pinned paths only)  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Rust extension install pin module
- Attack focus: manual ZIP/folder → `ManualZip` / `ManualFolder` + pinned (no auto-update);
  zip-slip / `..` fail-closed before write; tests use `FakeZipArchive` + `FakeExtensionInstallFs` only
  (no untrusted archive IO); replacement path confined under install root; reimport preserves
  stable path; save failure after move leaves files but not settings (C# parity); errors never embed
  hostile paths

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| BZ-001 | P1 | tests / harness | `FakeBitwardenExtensionSettingsStore` not `Clone` — glue tests would not compile | `settings.clone()` in import tests | **Fixed** — `Arc<Mutex<FakeSettingsInner>>` + `Clone` |
| BZ-002 | P1 | `replacement_install_path` | `canonicalize()` broke Fake logical paths | Tests use `C:\WormholeTest\…` not on disk | **Fixed** — lexical `ensure_confined_under` only |
| BZ-003 | P2 | `lib.rs` | Duplicate `parse_github_sha256` export vs CLI glue | `cargo build` name collision | **Fixed** — reuse CLI helper; drop duplicate from extension module |
| BZ-004 | P2 | `BitwardenExtensionSettingsSnapshot` | `Default` required on `source` enum | `cargo build` E0277 | **Fixed** — `#[default] OfficialGitHub` on enum |
| BZ-005 | P2 | `configured_install` | `manifest.version.map(sanitize…)` type mismatch | `cargo build` E0631 | **Fixed** — `as_deref().map(sanitize_browser_version)` |
| BZ-006 | P2 | `unique_install_path` | `bitwarden_extension_install_dir` points at profile root, not injectable test root | Installs could escape test `install_root` | **Fixed** — join `file_name()` under injectable root when prefixes differ |
| BZ-007 | P2 | docs | Ledger + README + feature-matrix + `04` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| BZ-R1 | — | live `zip` crate | Production could unzip untrusted archives | Task = Lab Fake glue; C# uses `ZipFile` | **Rejected** — `FakeZipArchive` + `confined_zip_destination` only; real IO later |
| BZ-R2 | — | `wormhole-http` home | Task allowed http or secrets crate | Install/pin + path confinement belong with `paths` + settings glue | **Rejected** — correct crate |
| BZ-R3 | — | Merge with CLI install glue | Both Bitwarden install surfaces | Distinct settings keys + ZIP vs CLI release assets | **Rejected** — separate modules |
| BZ-R4 | — | `VaultLocked` style error on pinned update | Could return explicit enum | `PinnedSource` + `reject_auto_update_if_pinned` suffices | **Rejected** |
| BZ-R5 | — | SHA-256 directory hash on every folder import | C# computes; adds Fake FS walk | Parity kept; Fake `list_files_recursive` only | **Rejected** — documented |

## Fixes applied

- `bitwarden_extension_install.rs` — pin glue + `FakeExtensionInstallFs` / `FakeZipArchive` / settings Fake + parity tests
- `lib.rs` / `Cargo.toml` — module, re-exports, crate doc blurb
- `docs/migration/04-secrets.md` — extension install pin section + non-goals tweak
- `docs/migration/feature-matrix.md` — manual ZIP/folder row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-bitwarden-zip-pin.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|---|
| Adv-0 | Contract → C# parity → zip-slip → Fake-only tests → path confinement → persist atomicity | BZ-001…007 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → replacement path → pinned update gate → error redaction | None (BZ-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: reimport stable path, save failure, unsafe zip no outside write | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `ensure_confined_under` + `bitwarden_extension_install_dir`; single `activate_install` | No `zip` dep; Fake FS only in tests | Zip-slip before write; pinned clears last check | None | Clean (1/3) |
| Sim-2 | `Arc` for Fake settings + Fake FS; `reject_auto_update_if_pinned` thin wrapper | Dropped duplicate `parse_github_sha256` | No GPUI / HTTP churn | None | Clean (2/3) |
| Sim-3 | No further extraction | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib bitwarden_extension
cargo test -p wormhole-secrets-win
```

**Result (final):** `bitwarden_extension` filter **12** passed; full crate **195** passed; 0 failed; 0 warnings.

```powershell
git diff --check -- rust/crates/wormhole-secrets-win/src/bitwarden_extension_install.rs rust/crates/wormhole-secrets-win/src/lib.rs docs/migration/adversarial-ledger-bitwarden-zip-pin.md docs/migration/04-secrets.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live GitHub download / GPUI / WebView2 extension host churn.
