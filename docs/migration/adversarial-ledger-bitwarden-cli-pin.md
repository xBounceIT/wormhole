# Adversarial ledger — Bitwarden CLI install pin (`wormhole-secrets-win`)

**Scope:**
- `rust/crates/wormhole-secrets-win/src/bitwarden_cli_install_glue.rs`
- Path helpers `bitwarden_cli_install_dir` / `bitwarden_cli_download_cache_dir` in `paths.rs`
- Crate-root re-exports in `lib.rs` / `Cargo.toml` description
- Docs: `04-secrets.md`, `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# `BitwardenCliInstaller` HTTP download / ZIP extract / `SemaphoreSlim` gate;
`BitwardenCliVaultClient` / `bw` process spawn; `wormhole-storage` settings adapter;
GPUI Settings install button; live GitHub `releases` API.

**Compared against:** C# `BitwardenCliInstaller` + `BitwardenCliInstallerTests`  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: no Rust CLI install module; feature-matrix row **Pending**
- Attack focus: empty version / empty or malformed SHA-256 pin fail-closed; hash mismatch
  before persist; configured external path short-circuit (no scripted install); release helper
  parity (`cli-v`, `bw-windows-*.zip`, `sha256:` digest); Debug/errors never embed digest or
  artifact bytes; no network / no `bw` spawn; save failure does not bump save count

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| BCP-001 | P1 | `install_pinned` | Malformed 64-char non-hex pin unpinned | Adv-1 boundary lane | **Fixed** — `parse_github_sha256` gate → `EmptySha256` test |
| BCP-002 | P1 | `resolve_executable_path` | `.exe` candidate duplicated (`[path, path]`) | C# single candidate when ends with `.exe` | **Fixed** — `Vec` with one entry |
| BCP-003 | P2 | `paths.rs` | No Rust path helpers for CLI install/cache roots | C# `AppPaths.GetBitwardenCli*` | **Fixed** — `bitwarden_cli_install_dir` + `bitwarden_cli_download_cache_dir` |
| BCP-004 | P2 | tests | `Arc<FakeSettings>` impl required `Arc` import at module scope | Compile E0425 | **Fixed** — test uses direct `FakeBitwardenCliInstallSettings` |
| BCP-005 | P2 | docs | Ledger + README + feature-matrix + `04` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| BCP-R1 | — | ZIP extract in Fake | C# downloads ZIP; lab uses pre-built `executable_bytes` | Task: Fake glue, no download | **Rejected** — documented; production adds ZIP later |
| BCP-R2 | — | `wormhole-ui` home | Task preferred UI or secrets crate | Install + hash verify belong with secrets paths | **Rejected** — correct crate |
| BCP-R3 | — | Re-verify hash on `ensure_installed` | C# does not re-hash existing binary | External path trust matches C# | **Rejected** |
| BCP-R4 | — | Orphan `bw.exe` when `save_install` fails after write | Rare lab edge; C# similar staging rollback scope | **Rejected** — documented; host may delete install root |
| BCP-R5 | — | Add `zip` crate for lab ZIP tests | Raw executable bytes sufficient for pin contract | **Rejected** |

## Fixes applied

- `bitwarden_cli_install_glue.rs` — glue + Fakes + C# release parsers + fail-closed tests
- `paths.rs` — CLI install + download cache roots under `%LOCALAPPDATA%\Wormhole\…`
- `lib.rs` / `Cargo.toml` — module, re-exports, path exports, crate description
- `docs/migration/04-secrets.md` — CLI install pin section + non-goals tweak
- `docs/migration/feature-matrix.md` — install row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-bitwarden-cli-pin.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → C# parity helpers → pin/hash gates → Debug redaction → Fake harness | BCP-001…005 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → external short-circuit → malformed pin → save atomicity | None (BCP-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: `ensure_installed` vs `install_pinned`, unique install dir suffix, path roots under Wormhole | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `sha2` workspace pin; settings/release traits mirror catalog Fakes | No `reqwest` / `zip` deps | Fail-closed errors fixed copy only | None | Clean (1/3) |
| Sim-2 | `lab_pinned_release` test helper; `glue_with_roots` only in tests | Inline `configured_version_label` | No storage/UI churn | None | Clean (2/3) |
| Sim-3 | No further extraction | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib bitwarden_cli
cargo test -p wormhole-secrets-win
```

**Result (final):** `bitwarden_cli` filter **13** passed; full crate **196** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-secrets-win/src/bitwarden_cli_install_glue.rs rust/crates/wormhole-secrets-win/src/paths.rs rust/crates/wormhole-secrets-win/src/lib.rs docs/migration/adversarial-ledger-bitwarden-cli-pin.md docs/migration/04-secrets.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live GitHub HTTP / `bw` spawn / GPUI churn.
