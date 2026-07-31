# 15 — Cutover / installer notes

**Status:** planning only — **do not** cut over production until surface-lab
gates reach `HardwarePass` on **both x64 and ARM64** (see
[gate-checklist.md](gate-checklist.md) +
[gate-evidence-log.md](gate-evidence-log.md)).  
**Date:** 2026-07-31  

**WinUI 3 remains the production shipping app.** The Rust/GPUI tree under
`rust/` is a parallel migration. The Rust Inno spike in
[18-rust-installer.md](18-rust-installer.md) is a **preview / lab channel only**
— it is **not** the shipping installer and must not replace
[`installer/Wormhole.iss`](../../installer/Wormhole.iss) until cutover is
explicitly approved. This doc captures how a future installer/cutover should
coexist with the current Inno Setup pipeline without stranding user data.

---

## Gate reminder (hard stop)

Before any production cutover or “Rust is default” installer change, every
required gate must be `HardwarePass` in
[gate-evidence-log.md](gate-evidence-log.md) for **x64 and ARM64**, and the
matching cells in [gate-checklist.md](gate-checklist.md) must be ticked only
after that evidence exists:

| Requirement | Doc |
|---|---|
| Gates **1–2** = `HardwarePass` on **x64 and ARM64** | [gate-checklist.md](gate-checklist.md), [gate-evidence-log.md](gate-evidence-log.md) |
| Gates **3–8** = `HardwarePass` on both arches (or kill-switch / suspend decision documented) | same — kill switches on 3–8 |
| Evidence pack per arch (DPI, light/dark, logs, commit SHA) | gate checklist “Evidence pack”; log upgrade steps in evidence log |
| Adversarial review of cutover PR | [adversarial-review-policy.md](adversarial-review-policy.md) |

**`LabOnly` ≠ pass.** Do not invent or imply `HardwarePass`. As of this note’s
date the evidence log stubs gates 1–8 as `LabOnly` only — **no** hardware
sign-off is claimed here. Lab CI / agent `cargo test` green is necessary but
**not** sufficient (especially gates 3–8: WebView2 z-order, RDP OCX, focus,
a11y).

Until that bar is met: keep shipping WinUI via the existing Inno channel; keep
Rust as side-by-side / lab / spike only (see [18-rust-installer.md](18-rust-installer.md)).

---

## Inno parallel-install strategy

Current installer: [`installer/Wormhole.iss`](../../installer/Wormhole.iss) +
[`scripts/Build-Installer.ps1`](../../scripts/Build-Installer.ps1).

| Today (WinUI) | Parallel Rust (proposed) |
|---|---|
| `AppId={{6E3A0D9E-…}}` | **Different** `AppId` (new GUID) so Add/Remove Programs lists two products |
| `DefaultDirName={autopf}\Wormhole` | e.g. `{autopf}\Wormhole Lab` or `Wormhole Native` — **never** overwrite WinUI dir while both ship |
| `Wormhole.exe` | Distinct exe name (`WormholeNative.exe` / `surface-lab.exe`) during preview |
| Output `Wormhole-{ver}-win-{arch}-setup` | Separate artifact name (`…-native-setup` / `…-lab-setup`) |
| Same `%LOCALAPPDATA%\Wormhole\` data | **Shared** by design (see compatibility below) |

### Rules

1. **Do not** replace the WinUI Inno script in place until cutover decision is explicit.
2. Preview / lab installers must be uninstallable independently (own `AppId` + Start Menu shortcut).
3. Optional task: “Also install Wormhole (WinUI)” is **not** required — prefer two setups.
4. Rollback = keep using WinUI installer / existing install; uninstall only the Rust preview.

### Rollback (keep WinUI)

- Leave WinUI installed and pinned as the daily driver.
- Uninstall the Rust preview via its own ARP entry.
- User profile under `%LOCALAPPDATA%\Wormhole\` stays intact (SQLite, CredMgr, DPAPI files, WebView2 profiles).
- Do **not** delete `wormhole.db`, `keys\`, `tunnels\`, `app-auth.dpapi`, or `bitwarden-browser-*` as part of Rust uninstall.

---

## DB / secrets compatibility checklist

Rust crates must stay **byte-compatible** with the shipping .NET app so either
host can open the same profile. Verify before any dual-write or cutover:

### SQLite (`wormhole.db`)

| Item | Expectation | Doc / crate |
|---|---|---|
| Path | `%LOCALAPPDATA%\Wormhole\wormhole.db` | [03-storage.md](03-storage.md) |
| Migrations | Same embedded `.sql` order / `__migration_history` | `wormhole-storage` |
| Schema | No Rust-only columns until a coordinated migration ships in **both** trees | |
| Concurrency | One writer at a time — do not run WinUI + Rust hosts against the DB simultaneously in v1 preview | |

### Secrets / paths

| Store | Entropy / keying | Rust helper |
|---|---|---|
| CredMgr `Wormhole:<guid:D>` | N/A | `wormhole-secrets-win` CredMgr API |
| `keys\<guid:N>.dpapi` | null | `key_path` / `write_key_payload(_under)` (path-confined) |
| `tunnels\<guid:N>.dpapi` | null | `tunnel_path` / `write_tunnel_payload(_under)` (path-confined) |
| `app-auth.dpapi` | UTF-8 `Wormhole.AppAuthentication.v1` | `app_auth` + `APP_AUTHENTICATION_V1` |
| `bitwarden-browser-storage.dpapi` | UTF-8 `Wormhole.BitwardenBrowser.SharedStorage.v1` | entropy + path |
| Azure / WatchGuard / Stormshield caches | `Guid.ToByteArray()` | `tunnel_id_entropy` |
| Bitwarden WebView2 profiles | `bitwarden-browser-webview2\profile-*` | paths in secrets-win; folder fingerprint in `wormhole-http::bitwarden` |

### App lock / Windows Hello

| Piece | Status in Rust |
|---|---|
| DPAPI protect/unprotect of verifier store | Stub unlock API (`unlock_app_authentication_store`); wrong entropy → `DpapiUnprotect`; `AppAuthUnlock` Debug redacts plaintext |
| PBKDF2 PIN/password verify | Still C# (`AppAuthenticationService`) — port later |
| Interactive Hello UI | **WinRT gap** — `UserConsentVerifier` **not** wired; `StubHelloPrompt` / `check_hello_availability` / `request_hello_verification` always fail closed (`available`/`verified` = false) with either the remote-session message or `WINRT_HELLO_GAP`. Tests use `FakeHelloPrompt` (no biometric UI; `Debug` omits freeform messages / never retains prompts). |
| Hello unlock prompt UI glue | Spike in `wormhole-app::hello_unlock` — `HelloUnlockGlue` / `FakeHelloUnlockUi` map request-unlock → Success / Cancelled / Unavailable (fail-closed; no GPUI / no live WinRT; Debug never retains prompts / biometric material). Not a hardware gate. |
| Remote-session gate | Implemented (`SM_REMOTESESSION` / `SESSIONNAME` `RDP-` prefix) — does **not** imply Hello can succeed on a local console |
| Bitwarden CLI unlock / `BW_SESSION` | **CLI gap — not production-wired** — `StubBitwardenSession` always locked / unlock fails with `BITWARDEN_CLI_SESSION_GAP`; no `bw` spawn; ignores `BW_SESSION` / `WORMHOLE_BW_PASSWORD` env (no silent unlock). Tests use `FakeBitwardenSession` (no process; memory-only opaque keys; empty / whitespace master password fails closed and clears any held key; empty / whitespace scripted key fails closed; `BitwardenSessionKey::is_empty` is whitespace-aware like C# `HasSessionKey`; Debug redacts — assert via `expose()`). Session key never persists to SQLite/backup. **Separate** from Bitwarden browser WebView2 profiles (`wormhole-http::bitwarden` / path helpers). |

**Do not** treat `cargo test -p wormhole-secrets-win` (or any agent CI) as a
Windows Hello / hardware gate pass. Lab green ≠ `HardwarePass` in
[gate-evidence-log.md](gate-evidence-log.md) for surface-lab gates on real
x64/ARM64 hardware.

### Settings / sidecars

| Item | Note |
|---|---|
| `settings.json` | MCP flag/port only; token remains CredMgr |
| VPN sidecars | Same exe names beside the host; MSBuild stages them for WinUI — Rust preview must ship or locate the same binaries |
| WebView2 Runtime | Evergreen Runtime on machine; do not assume MSIX package identity |

### Smoke checklist before declaring “compatible”

- [ ] Open a profile created by WinUI in Rust storage/secrets tests (or a read-only lab host).
- [ ] Round-trip one CredMgr password and one null-entropy key file.
- [ ] Unprotect `app-auth.dpapi` with `APP_AUTHENTICATION_V1` (if present).
- [ ] Confirm Bitwarden profile folder names match for the same browser args + cert flag.
- [ ] Confirm migration history matches after WinUI cold start (no unexpected pending migrations).

---

## Related docs

- [gate-checklist.md](gate-checklist.md) — x64/ARM64 acceptance boxes (tick only after `HardwarePass`)  
- [gate-evidence-log.md](gate-evidence-log.md) — `Pending` / `LabOnly` / `HardwarePass` status (no invented passes)  
- [18-rust-installer.md](18-rust-installer.md) — Rust artifact staging + parallel Inno **spike** (≠ shipping channel; WinUI untouched)  
- [04-secrets.md](04-secrets.md) — CredMgr / DPAPI / entropy / Hello stubs  
- [10-http.md](10-http.md) — HTTP targets + Bitwarden HTTPS profile helpers  
- [01-surface-lab.md](01-surface-lab.md) — how to run gates  
- [00-baseline.md](00-baseline.md) — packaging baseline tag  
- [adversarial-ledger-hello-cutover.md](adversarial-ledger-hello-cutover.md) — Hello / app-auth / Bitwarden / cutover review  
- [adversarial-ledger-hello-stub.md](adversarial-ledger-hello-stub.md) — Hello AvailabilityProbe / HelloPrompt stub review  

---

## Explicit non-goals (this phase)

- Treating the Rust Inno spike as the production shipping channel  
- Replacing `Wormhole.iss` AppId / DefaultDirName  
- Removing the .NET / WinUI app from CI or release  
- Dual-process write to `wormhole.db`  
- Shipping Rust as the default Start Menu entry  
- Claiming `HardwarePass` without real x64+ARM64 evidence in the gate evidence log  
