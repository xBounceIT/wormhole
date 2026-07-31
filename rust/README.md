# Wormhole Rust / GPUI migration workspace

Parallel scaffolding for the Phase-1 **surface lab** and native HWND broker.
This tree does **not** replace the .NET / WinUI 3 app; it is a technical gate
before any domain (InheritanceResolver) port.

## Targets

| Target | Status |
|--------|--------|
| `x86_64-pc-windows-msvc` | Primary (matches .NET x64) |
| `aarch64-pc-windows-msvc` | Intended (matches .NET arm64) |
| Other OS | Out of scope for this workspace |

Requires: existing stable Rust + MSVC Build Tools (same toolchain as WinUI).
Do not reinstall rustup on the documented machine — see [`docs/migration/toolchain.md`](../docs/migration/toolchain.md).

Agent shells may need:

```powershell
$env:Path = "C:\Users\dange\.cargo\bin;$env:Path"
```

## Crates

| Crate | Role |
|-------|------|
| [`surface-lab`](crates/surface-lab) | Phase-1 gate binary — prints gate checklist / stubs |
| [`wormhole-surface-win`](crates/wormhole-surface-win) | `NativeSurfaceBroker` API skeleton (bounds + kinds) |
| [`wormhole-domain`](crates/wormhole-domain) | Pure domain models + inheritance |
| [`wormhole-storage`](crates/wormhole-storage) | SQLite (rusqlite) + embedded `Data/Migrations` |
| [`wormhole-testkit`](crates/wormhole-testkit) | Shared fixtures (schema-only DB) |
| [`wormhole-secrets-win`](crates/wormhole-secrets-win) | CredMgr `Wormhole:<guid>` + DPAPI keys/tunnels/entropy |
| [`wormhole-terminal`](crates/wormhole-terminal) | PTY session trait + xterm bridge message types |
| [`wormhole-serial`](crates/wormhole-serial) | Tokio serial session (PuTTY-style settings) |
| [`wormhole-ssh`](crates/wormhole-ssh) | russh SSH spike (password + shell; SOCKS5 hooks) |
| [`wormhole-tunnels`](crates/wormhole-tunnels) | TunnelManager lease/coalesce + provider stubs |
| [`wormhole-mcp`](crates/wormhole-mcp) | Loopback MCP host stub (`rmcp` / HTTP placeholder) |
| [`wormhole-app`](crates/wormhole-app) | `AppServices` composition + tracing + bootstrap bin |
| [`wormhole-ui`](crates/wormhole-ui) | Shell state + optional GPUI chrome (`--features gpui`; `import` feature for mRemoteNG dialog VM; example `wormhole-ui-lab`) |
| [`wormhole-vnc`](crates/wormhole-vnc) | RFB subset: Raw pixel buffer + damage, input queue, session↔fb/input glue; optional `vnc-rs` |
| [`wormhole-http`](crates/wormhole-http) | `HttpConnectionTarget` + browser-arg helper |
| [`wormhole-import`](crates/wormhole-import) | mRemoteNG XML + backup envelope spike |
| [`wormhole-update`](crates/wormhole-update) | GitHub update check / SHA verify stubs |

## Build / run surface-lab

From this directory (`rust/`):

```powershell
# Default: no GPUI — always should compile on Windows MSVC
cargo check
cargo run -p surface-lab

# Optional features (when deps resolve cleanly on your machine)
cargo check -p surface-lab --features gpui
cargo check -p surface-lab --features webview
cargo check -p surface-lab --features rdp
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
```

Gate status mapping and how it ties to modules:
see [`../docs/migration/01-surface-lab.md`](../docs/migration/01-surface-lab.md).

## Design notes

- Native surfaces (WebView2, RDP ActiveX) are **not** drawn by GPUI.
  GPUI owns chrome/layout; `wormhole-surface-win` owns HWND lifecycle and
  physical-pixel bounds. RDP mirrors today's **owned overlay**
  (`GWLP_HWNDPARENT`), not `SetParent` — see
  [`../docs/migration/native-surface-broker.md`](../docs/migration/native-surface-broker.md).
- Domain / InheritanceResolver port stays blocked until surface gates pass; other
  workspace members may appear in parallel but are out of scope for this lab.
