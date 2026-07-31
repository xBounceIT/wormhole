# Adversarial ledger — Rust publish / Inno spike

**Scope:**
- `scripts/Build-Rust-Artifacts.ps1`
- `docs/migration/18-rust-installer.md`
- `installer/rust/Wormhole-Rust.iss.fragment`

**Out of scope:** `scripts/Build-Installer.ps1`, `installer/Wormhole.iss` (untouched), full cutover / hardware gates.

**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** DryRun exited 0 and created no `artifacts/` entries; hostile `-Packages '..\win-x64\Wormhole'` would stage into WinUI publish via `Join-Path` escape.  
**Final:** `-SelfTest` exit 0; `-DryRun` exit 0 (with and without cargo on PATH); no `artifacts/` writes from DryRun/SelfTest.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-confirmed after simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `Build-Rust-Artifacts.ps1 -SelfTest` | **pass** (exit 0) |
| `Build-Rust-Artifacts.ps1 -DryRun` | **pass** (exit 0, no artifact writes) |
| WinUI installer scripts | **untouched** |

---

## Accepted findings

### RI-01 — Package path injection overwrites WinUI publish (`P0`) — **fixed**

- **Where:** `Build-Rust-Artifacts.ps1` staging `Copy-Item` / `$pkg.exe`
- **Invariant:** Must not delete or overwrite `artifacts/publish/win-{arch}/`
- **Evidence:** `Join-Path rust-win-x64 "..\win-x64\Wormhole.exe"` → full path under `win-x64\Wormhole.exe`; DryRun accepted `-Packages '..\win-x64\Wormhole'`
- **Impact:** Hostile/mistyped `-Packages` could clobber shipping WinUI publish outputs
- **Fix:** Allowlist `wormhole-app`, `surface-lab`; `Get-StagedFilePath` leaf + containment under rust stage root
- **Regression:** `-SelfTest` rejects traversal packages; DryRun rejects same with exit ≠ 0

### RI-02 — Arbitrary cargo `-p` / flag-like package strings (`P1`) — **fixed**

- **Where:** `$Packages` → `cargo … -p $pkg`
- **Evidence:** DryRun printed `-p evil;calc` and `-p 'wormhole-app --manifest-path …'`
- **Impact:** Unexpected crate builds / arg confusion; coupled to RI-01 staging escape
- **Fix:** Same allowlist (exact names only)
- **Regression:** SelfTest bad-package list

### RI-03 — Inno fragment recursive `[Files]` would ship stage pollution (`P1`) — **fixed**

- **Where:** `Wormhole-Rust.iss.fragment` former `Source: "{#PublishDir}\*"` + `recursesubdirs`
- **Invariant:** Sidecar / stage copy must stay expected binary names; no recursive secrets
- **Impact:** Future real `.iss` would install any stray file left in the stage dir
- **Fix:** Explicit leaf `Source:` lines; `skipifsourcedoesntexist` for optional sidecars; comment forbidding recursive glob
- **Regression:** doc + fragment review

### RI-04 — Docs under-stated non-claims / PublishDir depth (`P2`) — **fixed**

- **Where:** `18-rust-installer.md`
- **Evidence:** Table showed `..\artifacts\…` for Rust while fragment lives under `installer/rust/` (`..\..\`); spike could be read as nearer cutover/gates than it is
- **Fix:** Explicit “Not claimed” (cutover / hardware gates / signed setup); correct `..\..\artifacts\publish\rust-win-{arch}`; non-goals bullet
- **Regression:** doc review

### RI-05 — CargoPath accepted non-cargo executables (`P2`) — **fixed**

- **Where:** `-CargoPath`
- **Evidence:** DryRun accepted `C:\Windows\System32\notepad.exe`
- **Impact:** Non-DryRun would invoke arbitrary exe named via path
- **Fix:** Leaf must be `cargo` / `cargo.exe`
- **Regression:** SelfTest + DryRun reject notepad

### RI-06 — Sidecar discovery not leaf-typed (`P2`) — **fixed**

- **Where:** `Find-SidecarSource`
- **Evidence:** `Test-Path` without `-PathType Leaf` could match a directory of the same name
- **Fix:** `-PathType Leaf` + leaf name must equal allowlisted `$Spec.Name`
- **Regression:** covered by leaf-only copy path + SelfTest containment

### RI-07 — DryRun required cargo on PATH (`P2`) — **fixed**

- **Where:** cargo resolution before DryRun
- **Invariant:** DryRun must exit 0 without writing; agents/CI may lack Rust
- **Fix:** DryRun resolves cargo best-effort; missing cargo prints placeholder and still exits 0; explicit bad `-CargoPath` still fails
- **Regression:** DryRun with fake `USERPROFILE` + stripped PATH → exit 0, no artifacts

### RI-08 — SelfTest hardcoded machine cargo path (`P3`) — **fixed**

- **Where:** SelfTest `Assert-CargoExecutablePath`
- **Fix:** `Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"`
- **Regression:** SelfTest exit 0

### RI-09 — Unicode em-dash broke PowerShell 5.1 string parse (`P1`) — **fixed**

- **Where:** DryRun message `cargo not found — …`
- **Evidence:** ParserError on PS 5.1; SelfTest/DryRun exit 1
- **Fix:** ASCII-only script text (em-dashes removed)
- **Regression:** SelfTest + DryRun exit 0 on Windows PowerShell 5.1

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| RI-R1 | P3 | Hash/Authenticode verify of `cargo.exe` — local trusted build tool; leaf check sufficient |
| RI-R2 | P3 | Wipe rust stage dir before copy — would add `Remove-Item` risk surface; leaf overwrite is enough |
| RI-R3 | P3 | Drop defense-in-depth `..` check after allowlist — keep for future allowlist edits |
| RI-R4 | P3 | Pester project — no Pester in repo; `-SelfTest` covers contracts |

---

## Simplify passes (3 clean)

1. **Reuse / efficiency / quality** — removed redundant early `$stageDir`; collapsed `$expectedStage` alias; no further validated churn.
2. **Reuse / efficiency / quality** — sidecar name parity script↔fragment confirmed; no findings.
3. **Reuse / efficiency / quality** — docs/fragment/script contracts aligned; no findings.

Post-simplify adversarial re-check (delta = stageDir cleanup only): no new accepted findings → **2 clean adversarial passes**.

---

## Verification

```powershell
.\scripts\Build-Rust-Artifacts.ps1 -SelfTest          # exit 0
.\scripts\Build-Rust-Artifacts.ps1 -Architecture x64 -DryRun   # exit 0, no artifacts/
# hostile:
.\scripts\Build-Rust-Artifacts.ps1 -DryRun -Packages '..\win-x64\Wormhole'   # exit ≠ 0
.\scripts\Build-Rust-Artifacts.ps1 -DryRun -CargoPath C:\Windows\System32\notepad.exe  # exit ≠ 0
git status --short -- scripts/Build-Installer.ps1 installer/Wormhole.iss   # clean
```

---

## Residual risks

- A binary literally named `cargo.exe` on a caller-supplied path can still be invoked (trusted local build).
- Real Inno compile of the fragment is still future work (`Build-Rust-Installer.ps1` not in this spike).
- Hardware surface-lab gates and cutover remain **not** claimed passed.
