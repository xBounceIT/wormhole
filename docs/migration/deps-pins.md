# Migration dependency pins (Rust / GPUI)

**Researched:** 2026-07-31  
**Synced against:** `rust/Cargo.toml` workspace pins (2026-07-31)  
**Audience:** agents applying or bumping pins in `rust/Cargo.toml`  
**Rule:** pin git **commit SHAs** (and exact crates.io versions). Do not float `main` / `*` / bare majors in the Wormhole lockfile.

Context7 MCP was not available in this environment; pins come from crates.io, GitHub APIs, and upstream READMEs/Cargo.toml.

### Sync status vs `rust/Cargo.toml`

| Pin | Docs / Cargo | Drift? |
|---|---|---|
| Zed `gpui` / `gpui_platform` rev | `9c7a5c9485669f57a22bc9c07b0f856cf1829a34` | **None** |
| `gpui-component` rev | `88f102d13654fe25aa2fede076274b6b751a3704` | **None** |
| `wry` | `=0.56.0` | **None** |
| `webview2-com` | `=0.38.2` | **None** |
| `raw-window-handle` | `=0.6.2` | **None** |
| `windows` | `=0.61.3` | **None** (feature list below matches workspace) |
| `windows-core` | `=0.61.2` | **None** (workspace direct pin) |

Do **not** bump these versions/SHAs from this doc alone — refresh text only when Cargo already moved, or after a coordinated bump PR.

---

## Current pin table

| Crate / source | Workspace pin | Why |
|---|---|---|
| `gpui` + `gpui_platform` | git `zed-industries/zed` **rev** `9c7a5c9485669f57a22bc9c07b0f856cf1829a34` | Zed `main` as of 2026-07-31; Windows uses Win32 + DirectWrite / DX11; `gpui_platform` is **not** on crates.io |
| `gpui` crates.io alone | **Avoid** as sole pin (`0.2.2`, 2025-10-22) | Stale vs current API; missing `gpui_platform` split |
| `gpui-component` | git `longbridge/gpui-component` **rev** `88f102d13654fe25aa2fede076274b6b751a3704` | Matches current component tree (package `0.5.2` in-tree; crates.io latest published `0.5.1`) |
| `gpui-wry` (experimental webview) | same gpui-component rev, package path `crates/webview` | Overlay-only; **not** for production SSH/HTTP surfaces |
| `wry` | `=0.56.0` | Latest crates.io (at pin time); Windows child webviews; aligns on `windows ^0.61` |
| `webview2-com` | `=0.38.2` (with wry) | Matches wry 0.56’s `webview2-com ^0.38`; **do not** take `0.39.x` while GPUI/wry stay on windows 0.61 |
| `windows` | `=0.61.3` | Same major as Zed GPUI workspace (`0.61`) and wry 0.56; RDP COM + HWND ownership (`GWLP_HWNDPARENT`) / WebView2 parenting / DPAPI / CredMgr |
| `windows-core` | `=0.61.2` | Direct pin for `#[implement]` consumers (`windows` 0.61 has no `implement` feature) |
| `raw-window-handle` | `=0.6.2` | Required by wry / GPUI HWND bridging |

**Do not** enable `gpui-ce` (`gpui-ce/gpui-ce`, tip `33ed975bf2dff2735eaa21366aa7fa19015c891c`) for Phase 1 unless Zed main regresses on Windows. Prefer upstream Zed so `gpui-component` stays drop-in; re-evaluate CE only with an explicit `[patch]` plan.

---

## 1. GPUI (Zed) — Windows + pinning strategy

### Status (2026-07-31)

- GPUI is pre-1.0; breaking changes are expected.
- Windows is first-class: Win32 windowing, DirectWrite text, DirectX 11 renderer (merged mid-2025).
- README: on Windows, `gpui_platform` needs **no** Linux features (`wayland` / `x11`). `font-kit` has no effect on Windows.
- Zed published `gpui` `0.2.2` to crates.io (2025-10-22) but continued evolving the monorepo. Standalone apps need **`gpui` + `gpui_platform`** from the same git rev.
- Zed has throttled non-editor GPUI work for 2026; community fork [gpui-ce](https://github.com/gpui-ce/gpui-ce) exists but tracks upstream with lag risk for `gpui-component`.

### Pin strategy

1. Pin **one** Zed commit SHA for both `gpui` and `gpui_platform`.
2. Pin `gpui-component` to a SHA known to build against that Zed rev (bump both together).
3. Commit `rust/Cargo.lock` once features are enabled.
4. Never depend on `gpui = "*"` or un-rev’d `git = "…/zed"`.

### Cargo snippets

```toml
[workspace.dependencies]
# Zed GPUI — pin SHA; bump only with a coordinated gpui-component bump + cargo check.
gpui = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34" }
gpui_platform = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34", default-features = false }

# UI kit (optional for surface-lab chrome). Same pin discipline.
gpui-component = { git = "https://github.com/longbridge/gpui-component", rev = "88f102d13654fe25aa2fede076274b6b751a3704" }
```

Consumer (Windows-only host):

```toml
[dependencies]
gpui = { workspace = true }
gpui_platform = { workspace = true } # Windows: leave default-features false; no wayland/x11
```

### Risks

| Risk | Mitigation |
|---|---|
| SHA rot / API break on bump | Bump Zed + gpui-component in one PR; run `cargo check -p surface-lab --features gpui` |
| crates.io `0.2.2` drift | Do not mix crates.io `gpui` with git `gpui_platform` |
| Large native graph | Keep GPUI behind `surface-lab` feature `gpui` (already scaffolded) |
| `gpui-component` floats Zed without rev | Our workspace must override with explicit revs; prefer `[patch]` if Cargo fails to unify |

If Cargo cannot unify gpui-component’s floating Zed git dep with our rev’d dep:

```toml
[patch."https://github.com/zed-industries/zed"]
gpui = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34" }
gpui_platform = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34", default-features = false }
gpui_macros = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34" }
```

---

## 2. gpui-component + experimental `gpui-wry` webview

### Pins

- Repo tip researched: `88f102d13654fe25aa2fede076274b6b751a3704` (2026-07-30).
- In-tree package version: `gpui-component` `0.5.2`; crates.io max published: `0.5.1`.
- Experimental webview crate name: **`gpui-wry`** (`crates/webview`, version `0.5.0`), depends on **`lb-wry` `0.53.3`** (Longbridge wry fork), **not** stock wry `0.56`.

### Documented limitations (upstream README + issues)

- WebView **renders on top of the GPUI window**; any GPUI chrome inside the webview bounds is covered (no GPUI z-order).
- macOS + Windows only.
- Maintainers recommend a **separate window** or **Popup / sheet** layer.
- Known focus issues: webview can steal keyboard focus from GPUI inputs ([longbridge/gpui-component#1787](https://github.com/longbridge/gpui-component/issues/1787)).
- Hide/show across tabs needs explicit teardown/lazy `Option` (overlay HWND does not participate in GPUI layout).

### Wormhole implication

Native session surfaces (xterm.js SSH, HTTP appliance UI, Fortinet SAML WebView2) must live in **`wormhole-surface-win`**, **not** inside `gpui-wry` for production.

Hosting model (see `native-surface-broker.md`):

- **WebView2** — in-tree / child composition (wry `build_as_child` or `webview2-com` controller); collapse visibility for background tabs.
- **RDP ActiveX** — **owned top-level overlay** (`GWLP_HWNDPARENT` + `WS_EX_TOOLWINDOW`), **not** `SetParent`/`WS_CHILD` (DirectComposition airspace).

Use `gpui-component` for chrome (tree, tabs chrome, dialogs). Treat `gpui-wry` as a spike-only dependency.

```toml
# OPTIONAL spike only — do not use for SSH/HTTP/SAML production surfaces.
# gpui-wry = { git = "https://github.com/longbridge/gpui-component", rev = "88f102d13654fe25aa2fede076274b6b751a3704", package = "gpui-wry" }
```

---

## 3. wry vs webview2-com (Windows child WebView2)

Wormhole needs: child HWND hosting, **SOCKS5** (VPN), **ignore cert errors** (HTTPS appliances / loopback bridge), **isolated user-data folders / profiles** (Fortinet SAML embedded login, Bitwarden-style isolation).

### Comparison

| Concern | `wry` `0.56.0` | `webview2-com` `0.38.2` |
|---|---|---|
| Child HWND | `WebViewBuilder::build_as_child` + `reparent` (`SetParent`) | Full control via `CreateCoreWebView2Controller` + parent HWND |
| SOCKS5 | `with_proxy_config(ProxyConfig::Socks5 { .. })` **or** `--proxy-server=socks5://…` via `with_additional_browser_args` | Environment / `--proxy-server` / custom; more boilerplate |
| Isolated profiles | `WebContext::new(Some(path))` + `with_profile_name` | Explicit `userDataFolder` + `ICoreWebView2Environment` / profile APIs |
| Browser args | `WebViewBuilderExtWindows::with_additional_browser_args` | `ICoreWebView2EnvironmentOptions::SetAdditionalBrowserArguments` |
| Cert policy (`ServerCertificateErrorDetected`) | **Not first-class** on wry builder; need controller/`ICoreWebView2` escape hatch | Direct event sink — closest to current C# `AlwaysAllow` path |
| `windows` crate | `^0.61` | `0.38.x` → `^0.61`; **`0.39.x` → `^0.62`** (conflicts with GPUI/wry) |

### Recommendation

| Surface | Stack |
|---|---|
| SSH / Serial xterm.js | **wry** `0.56.0` child webview + dedicated `WebContext` data dir under `%LOCALAPPDATA%\Wormhole\webview\terminal\` |
| HTTP/HTTPS session + SOCKS | Prefer **wry** proxy API first; fall back to `--proxy-server` args with a **matching unique data directory** |
| HTTPS ignore-cert / custom cert UI | **webview2-com** (or wry + `WebViewExtWindows` controller → `add_ServerCertificateErrorDetected`) |
| Fortinet SAML / Bitwarden-like isolated profile | Separate `userDataFolder` (and/or `with_profile_name`); never share UDF across different `additionalBrowserArgs` / proxy / scrollbar settings |

**Critical Windows WebView2 rule** (wry docs + Microsoft): environments that differ in `CoreWebView2EnvironmentOptions` (browser args, etc.) **must** use different user-data folders. Sharing a UDF with mismatched options → `HRESULT 0x8007139F` (“not in the correct state”). This matches Bitwarden/Tauri operational guidance.

### Cargo snippets

```toml
[workspace.dependencies]
wry = { version = "=0.56.0", default-features = false, features = ["os-webview"] }
# Stay on 0.38.x while wry/GPUI pin windows 0.61:
webview2-com = { version = "=0.38.2" }
raw-window-handle = { version = "=0.6.2" }
```

SOCKS via wry (preferred when sufficient):

```rust
// Conceptual — see wry::ProxyConfig / WebViewBuilder::with_proxy_config
builder.with_proxy_config(wry::ProxyConfig::Socks5(wry::ProxyEndpoint {
    host: socks_host.into(),
    port: socks_port,
}));
```

Cert ignore (webview2-com shape; mirrors C# `ServerCertificateErrorDetected = AlwaysAllow`):

```rust
// After obtaining ICoreWebView2:
// webview.add_ServerCertificateErrorDetected(...)?  // always allow when policy says so
```

Do **not** jump to `webview2-com 0.39.1` until the whole workspace moves to `windows 0.62` (Zed still on `0.61` as of the pin SHA above).

---

## 4. `windows` crate — MsRdpClient9 COM + HWND ownership

### Pin

Matches `rust/Cargo.toml` (includes secrets / CredMgr / DPAPI features used by `wormhole-secrets-win`):

```toml
# Direct pin for `#[implement]` consumers (windows 0.61 has no `implement` feature).
windows-core = { version = "=0.61.2" }

[workspace.dependencies.windows]
version = "=0.61.3"
features = [
    "Win32_Foundation",
    "Win32_Graphics_Gdi",
    "Win32_Security_Credentials",
    "Win32_Security_Cryptography",
    "Win32_Storage_FileSystem",
    "Win32_System_Com",
    "Win32_System_Com_StructuredStorage",
    "Win32_System_DataExchange",
    "Win32_System_LibraryLoader",
    "Win32_System_Memory",
    "Win32_System_Ole",
    "Win32_System_Registry",
    "Win32_System_Threading",
    "Win32_System_Variant",
    "Win32_UI_HiDpi",
    "Win32_UI_Input_KeyboardAndMouse",
    "Win32_UI_WindowsAndMessaging", # MoveWindow, ShowWindow, SetWindowLongPtr, …
]
```

### Why `0.61.3` (not `0.62.2` or `0.58`)

| Version | Role |
|---|---|
| `0.62.2` | Latest crates.io — **conflicts** with Zed GPUI (`0.61`) and wry `0.56` |
| **`0.61.3`** | **Workspace pin** — aligns Zed + wry + webview2-com `0.38` |
| `0.58.0` | What gpui-component’s workspace still declares — older; prefer our workspace pin of `0.61.3` for Wormhole crates |

MsRdpClient9 is **not** in Win32 metadata as a ready-made Rust class. Plan (mirror C# `RdpHostForm` owned overlay — see `native-surface-broker.md`):

1. Host ActiveX in an owned **top-level** HWND (WinForms-equivalent / ATL host), **not** `SetParent`/`WS_CHILD` into the GPUI surface (airspace).
2. Set owner via `GWLP_HWNDPARENT` (+ `WS_EX_TOOLWINDOW`); position with screen physical bounds each layout tick.
3. Keep RDP create/connect/events on an **STA** thread with a message pump (ActiveX requirement — unchanged from WinUI host).

`SetParent` may still appear for **WebView2 child** hosting (wry), not for RDP.

Also keep `windows-core = "=0.61.2"` so COM helpers match the `windows` 0.61 major.

### DPI risk

Mismatched DPI awareness between the GPUI owner window and native hosts fails or mis-scales on modern Windows. GPUI window + RDP overlay + WebView2 children must share the same DPI awareness (per-monitor V2 preferred, matching today’s WinUI app).

---

## 5. GPUI / WebView2 block (mirrors `rust/Cargo.toml`)

Excerpt of the surface-related pins already present in `rust/Cargo.toml` (path crates and other workspace pins live beside these — do not delete them when editing):

```toml
# Pins: docs/migration/deps-pins.md — bump SHAs only with coordinated cargo check.
gpui = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34" }
gpui_platform = { git = "https://github.com/zed-industries/zed", rev = "9c7a5c9485669f57a22bc9c07b0f856cf1829a34", default-features = false }
gpui-component = { git = "https://github.com/longbridge/gpui-component", rev = "88f102d13654fe25aa2fede076274b6b751a3704" }
wry = { version = "=0.56.0", default-features = false, features = ["os-webview"] }
webview2-com = { version = "=0.38.2" }
raw-window-handle = { version = "=0.6.2" }
# Direct pin for `#[implement]` consumers (windows 0.61 has no `implement` feature).
windows-core = { version = "=0.61.2" }

[workspace.dependencies.windows]
version = "=0.61.3"
features = [
    "Win32_Foundation",
    "Win32_Graphics_Gdi",
    "Win32_Security_Credentials",
    "Win32_Security_Cryptography",
    "Win32_Storage_FileSystem",
    "Win32_System_Com",
    "Win32_System_Com_StructuredStorage",
    "Win32_System_DataExchange",
    "Win32_System_LibraryLoader",
    "Win32_System_Memory",
    "Win32_System_Ole",
    "Win32_System_Registry",
    "Win32_System_Threading",
    "Win32_System_Variant",
    "Win32_UI_HiDpi",
    "Win32_UI_Input_KeyboardAndMouse",
    "Win32_UI_WindowsAndMessaging",
]
```

Suggested bump procedure:

1. Pick new Zed SHA → update `gpui` / `gpui_platform` rev.
2. Pick matching `gpui-component` SHA → update rev.
3. Re-check wry/webview2-com/`windows` majors still unify (`cargo tree -i windows`).
4. `cargo check -p surface-lab` and `cargo check -p surface-lab --features gpui`.
5. Refresh this doc’s sync table + snippets to match Cargo (docs-only; no silent version bumps).

---

## 6. Explicit non-goals / traps

- **Do not** use `lb-wry` / `gpui-wry` for production terminal or HTTP tabs.
- **Do not** put WebView2 or RDP pixels “inside” GPUI’s GPU scene; they are native overlays managed by `wormhole-surface-win`.
- **Do not** share one WebView2 user-data folder across SOCKS vs non-SOCKS, or across different `--proxy-server` / browser-arg sets.
- **Do not** enable `webview2-com 0.39` + `windows 0.62` until GPUI’s workspace `windows` pin moves.
- C# production code stays untouched; these pins apply only under `rust/`.
- **Import spike pins** (`wormhole-import`): `quick-xml =0.41.0`, `serde =1.0.229`, `serde_json =1.0.151`, `aes-gcm =0.11.0` (with `AesGcm<Aes256, U16>` for mRemoteNG’s 16-byte nonce), `pbkdf2 =0.12.2`, `sha1 =0.10.6`, `zeroize =1.9.0` (see `12-import.md`).

---

## 7. Source checklist (re-verify on bump)

| Source | What to check |
|---|---|
| https://github.com/zed-industries/zed/tree/main/crates/gpui | README Windows notes + workspace `windows` version |
| https://crates.io/crates/gpui | crates.io lag vs git |
| https://github.com/longbridge/gpui-component/tree/main/crates/webview | Overlay limitations + `lb-wry` version |
| https://docs.rs/wry/latest/wry/ | `build_as_child`, `WebContext`, `WebViewBuilderExtWindows` |
| https://crates.io/crates/webview2-com | windows major coupling (`0.38`→0.61, `0.39`→0.62) |
| https://crates.io/crates/windows | Latest vs GPUI-compatible pin |
| `rust/Cargo.toml` | Authority for applied SHAs / exact versions — keep this doc in sync |
