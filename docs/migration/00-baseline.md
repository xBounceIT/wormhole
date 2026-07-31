# Phase 0 — Baseline snapshot

Inventory date: **2026-07-31** (reconfirmed)  
Scope: shipped WinUI 3 / .NET 10 Wormhole app as migration source-of-truth for a future **Rust / GPUI** rewrite.  
This document records *what exists today in production*, not the target architecture.

## Honesty (migration posture)

| Claim | Status |
|---|---|
| Production app | **WinUI 3 / .NET 10** — still the only shipping product |
| App version | **0.9.0** (`Wormhole.csproj`); git tag **`v0.9.0`** points at the baseline commit |
| Rust / GPUI | **Parallel workspace** under [`rust/`](../../rust/) (Cargo workspace + migration docs). Lab / spike / crate landing only |
| Cutover | **Not done** — do not treat Rust as default or replace the WinUI installer until Phase 7 / explicit approval (see [`15-cutover.md`](15-cutover.md)) |

Reconfirmed 2026-07-31 via `git rev-parse HEAD`, `git log -1`, and `git describe --tags` on this worktree tip (still the baseline commit below; uncommitted `rust/` / `docs/migration/` work may sit beside it).

## Git baseline

| Field | Value |
|---|---|
| Commit | `fc0337e0e8b4d6178ddf6c6838b1c45a8aecf60f` |
| Tag | `v0.9.0` |
| Subject | Fix terminal bridge CA1859 warnings (#296) |
| Author | Daniel D'Angeli \<35002896+xBounceIT@users.noreply.github.com\> |
| Date | 2026-07-29 17:33:27 +0200 |
| Branch (worktree) | `cursor/36afab15` (same tip as `main` / `origin/main` at inventory time) |
| App version (csproj) | **0.9.0** (`AssemblyVersion` 0.9.0.0) |
| License | AGPL-3.0-or-later |

Commands used:

```text
git rev-parse HEAD
git log -1
git describe --tags
```

## Runtime / platforms

| Item | Value |
|---|---|
| UI stack | WinUI 3 (`Microsoft.WindowsAppSDK` 2.1.3) + custom title bar / Mica |
| TFM | `net10.0-windows10.0.19041.0` (min OS **Windows 10 19041**) |
| Platforms | **x64**, **arm64** only (`Platforms` / `RuntimeIdentifiers`: `win-x64;win-arm64`) — **no x86** |
| Packaging | **Unpackaged** (`WindowsPackageType=None`) |
| DPI | Per-monitor V2 (`app.manifest`) |
| Extra frameworks | `Microsoft.WindowsDesktop.App.WindowsForms` (RDP ActiveX host), `Microsoft.AspNetCore.App` (in-app MCP / Kestrel) |
| Evergreen deps | WebView2 Runtime (SSH terminal, HTTP/HTTPS, SAML / Entra popups, changelog, Bitwarden extension profiles) |

## Packaging & distribution notes

- **Installer**: Inno Setup 6 (`installer/Wormhole.iss`) driven by `scripts/Build-Installer.ps1`.
- Publish is **self-contained** for `win-x64` / `win-arm64` so the ASP.NET Core shared framework (MCP) ships with the app — no separate .NET prerequisite on target machines.
- Output name pattern: `Wormhole-{version}-win-{arch}-setup`.
- Sidecars staged beside the exe (MSBuild `Fetch*` targets; missing Go/C++ toolchain **warns** in Debug, OpenVPN Release defaults to fail-closed via `RequireRealOvpnProxy`):
  - `wormhole-wgproxy.exe` — WireGuard
  - `wormhole-ovpnproxy.exe` — OpenVPN (+ WatchGuard / Stormshield / Azure VPN data plane)
  - `wormhole-fortiproxy.exe` — Fortinet SSL VPN
  - `wormhole-ciscoproxy.exe` — Cisco Secure Client / AnyConnect
- Web assets: xterm.js under `Assets/web/` (fetched/verified by `scripts/Fetch-WebAssets.ps1`).
- WER local dumps registered under `%LOCALAPPDATA%\Wormhole\crashdumps` by the installer.
- **Do not switch to MSIX** without re-auditing the ActiveX / WAM / airspace path (documented risk in `AGENTS.md`).
- Rust parallel Inno / artifact scripts (`installer/rust/`, `scripts/Build-Rust-Artifacts.ps1`) are **spikes** — they do not replace `installer/Wormhole.iss`.

## On-disk app state (non-secret layout)

Root: `%LOCALAPPDATA%\Wormhole\`

| Path | Purpose |
|---|---|
| `wormhole.db` | SQLite connection tree, credentials metadata, tunnels metadata, Bitwarden item cache |
| `settings.json` | App settings (schema v8) — no passwords / MCP token |
| `app-auth.dpapi` | App unlock secret (PIN / password verifier), DPAPI CurrentUser + fixed entropy |
| `keys\*.dpapi` | SSH private keys (DPAPI) |
| `tunnels\*.dpapi` | Tunnel provider secret payloads (DPAPI) |
| `stormshield-cache\`, `watchguard-cache\`, `azurevpn-cache\` | Per-tunnel DPAPI caches (profiles / refresh tokens) |
| `logs\`, `crashdumps\`, `cache\updates\` | Diagnostics / update downloads |
| `webview2*\`, `*-webview2\`, `webview2-web\` | WebView2 user-data roots (argument-keyed subfolders) |
| `tools\bitwarden-cli\`, `extensions\bitwarden\`, `bitwarden-browser-storage.dpapi` | Optional Bitwarden CLI + browser extension |

Windows Credential Manager entries use application name `Wormhole:<guid>` (saved passwords, inline connection passwords, MCP bearer token at fixed guid `a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91`).

## Schema / migrations

Embedded SQL under `Data/Migrations/` applied alphabetically by `Data/MigrationRunner.cs` into `__migration_history`. Latest at baseline: `0015_bitwarden_credential_cache.sql` (plus historical dual `0003_*` / `0007_*` files that already shipped).

## Explicitly out of scope for “shipped” (Planned in README)

Telnet; advanced VNC auth beyond no-auth / classic password; External Tools templating; port-scan → add connection; Windows Hello as *credential vault* unlock alternative to local store (app-lock Hello **is** shipped); 1Password / Azure Key Vault providers; SSH port-forwarding UI; Ctrl+K command palette.

## Companion docs

- [`feature-matrix.md`](feature-matrix.md) — exhaustive shipped feature matrix
- [`interop-inventory.md`](interop-inventory.md) — Win32 / COM / WebView2 / DPAPI / CredMgr touchpoints for NativeSurfaceBroker & secrets crates
- [`15-cutover.md`](15-cutover.md) — future cutover checklist (not executed)
- [`README.md`](README.md) — migration doc index + Rust workspace map
