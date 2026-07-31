# 18 — Rust publish + Inno parallel channel (spike)

**Status:** planning / spike only — **do not** replace the shipping WinUI installer.  
**Date:** 2026-07-31  

This note documents how to publish Rust binaries and wire a **second** Inno
Setup channel beside the existing .NET pipeline. Production cutover rules,
shared profile compatibility, and rollback remain owned by
[15-cutover.md](15-cutover.md).

**Not claimed by this spike:** cutover approval, surface-lab hardware gates
(x64/ARM64), or signed production Rust setup. See
[gate-checklist.md](gate-checklist.md) — those remain open until explicitly
passed on real hardware.

---

## What already ships (do not break)

| Piece | Role |
|---|---|
| [`scripts/Build-Installer.ps1`](../../scripts/Build-Installer.ps1) | `dotnet publish` self-contained → ISCC on `Wormhole.iss` |
| [`installer/Wormhole.iss`](../../installer/Wormhole.iss) | WinUI `AppId`, `{autopf}\Wormhole`, `Wormhole.exe` |
| Output | `installer/output/Wormhole-{ver}-win-{arch}-setup.exe` |

**Rule:** leave those files’ shipping behavior unchanged until an explicit
cutover decision (gates + adversarial review per [15-cutover.md](15-cutover.md)).

---

## Rust artifact staging (today)

Script: [`scripts/Build-Rust-Artifacts.ps1`](../../scripts/Build-Rust-Artifacts.ps1)

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
.\scripts\Build-Rust-Artifacts.ps1 -Architecture x64 -DryRun
.\scripts\Build-Rust-Artifacts.ps1 -Architecture x64 -SelfTest
.\scripts\Build-Rust-Artifacts.ps1 -Architecture x64
```

| Step | Detail |
|---|---|
| Build | `cargo build --release --target <triple> -p wormhole-app -p surface-lab` in `rust/` |
| Packages | Allowlisted only: `wormhole-app`, `surface-lab` (rejects path-like / arbitrary `-p` targets) |
| Triple | `x64` → `x86_64-pc-windows-msvc`; `arm64` → `aarch64-pc-windows-msvc` |
| Stage dir | `artifacts/publish/rust-win-{arch}/` only (parallel to `artifacts/publish/win-{arch}/`; never writes WinUI publish) |
| Binaries | `wormhole-app.exe`, `surface-lab.exe` (leaf names; destination containment checked) |
| Sidecars | **Leaf copy only** of expected names from `obj/<name>/{arch}/`, `tools/<name>/`, or `bin/` — `wormhole-wgproxy.exe`, `wormhole-ovpnproxy.exe`, `wormhole-fortiproxy.exe`, `wormhole-ciscoproxy.exe`. No recursive tree copy. Missing sidecars are non-fatal. |

Optional: run the existing `scripts/Fetch-*.ps1 -Arch x64` first so `obj\…` has binaries to stage.

`-DryRun` prints planned cargo args and sidecar discovery **without creating or writing** under `artifacts/`. It still validates packages / stage paths and exits 0.  
`-SelfTest` exercises allowlist + path-containment regressions without building.

---

## Two Inno strategies (neither removes WinUI)

### A — Parallel script / channel (recommended for preview)

Keep `Wormhole.iss` as-is. Add a **separate** script (stub comments:
[`installer/rust/Wormhole-Rust.iss.fragment`](../../installer/rust/Wormhole-Rust.iss.fragment)):

| WinUI (shipping) | Rust preview |
|---|---|
| `AppId={{6E3A0D9E-…}}` | **New** GUID |
| `DefaultDirName={autopf}\Wormhole` | e.g. `{autopf}\Wormhole Lab` — never overwrite WinUI dir |
| `Wormhole.exe` | `wormhole-app.exe` / `surface-lab.exe` during preview |
| `PublishDir=..\artifacts\publish\win-{arch}` (from `installer/`) | `..\..\artifacts\publish\rust-win-{arch}` (from `installer/rust/`) |
| Output `…-setup` | Distinct name, e.g. `WormholeLab-{ver}-win-{arch}-setup` |

`[Files]` in the fragment lists **explicit** exe names (with
`skipifsourcedoesntexist` for optional sidecars). Do **not** use
`{#PublishDir}\*` + `recursesubdirs` — that would ship anything left in the
stage directory.

Wire a future `Build-Rust-Installer.ps1` that:

1. Calls `Build-Rust-Artifacts.ps1` (or assumes stage dir is warm).
2. Invokes `ISCC.exe` on the Rust `.iss` only — **not** on `Wormhole.iss`.

Two ARP entries, two uninstallers, independent rollback.

### B — Second `[Files]` / `#ifdef` section inside one `.iss`

Possible later for a single download that installs “Lab” as an optional task, but
riskier: shared `AppId` / upgrade path can confuse ARP and uninstall.

If explored:

- Prefer `#ifdef RustLab` / `/DRustLab=1` compile-time branches over mutating the
  default WinUI-only compile.
- Keep WinUI files + icons as the default path when the define is absent.
- Still use a **different** install directory (or optional task that never
  replaces `Wormhole.exe`) so rollback does not require reinstalling WinUI.

Until cutover is approved, prefer **strategy A**.

---

## Rollback (points at cutover doc)

Follow [15-cutover.md § Rollback](15-cutover.md) and the parallel-install table there:

1. Keep using the WinUI installer / existing `{autopf}\Wormhole` install.
2. Uninstall only the Rust preview (its own `AppId`).
3. Leave `%LOCALAPPDATA%\Wormhole\` intact (SQLite, CredMgr, DPAPI, WebView2 profiles).
4. Do **not** treat Rust uninstall as permission to delete `wormhole.db`, `keys\`, `tunnels\`, or `app-auth.dpapi`.

Hard stop before making Rust the default Start Menu entry: surface-lab gates on
real x64/ARM64 hardware ([gate-checklist.md](gate-checklist.md)). This spike
does **not** mark those gates passed.

---

## Explicit non-goals (this spike)

- Changing `installer/Wormhole.iss` `AppId` / `DefaultDirName` / `[Files]`
- Replacing or deleting `scripts/Build-Installer.ps1`
- Shipping a signed production Rust setup
- Dual-process write to `wormhole.db`
- Claiming cutover or hardware gate completion

---

## Related

- [15-cutover.md](15-cutover.md) — parallel install, DB/secrets checklist, rollback  
- [toolchain.md](toolchain.md) — cargo PATH for agents  
- [07-tunnels-mcp.md](07-tunnels-mcp.md) — sidecar locate beside host  
- [adversarial-ledger-rust-installer.md](adversarial-ledger-rust-installer.md) — adversarial review of this spike  
