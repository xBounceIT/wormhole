ï»¿# Tunnels + MCP scaffolding (Rust migration)

**Status:** `TunnelManager` lease glue (ref-counted coalesce ? `UpdatedAt` + Failed/Closed fail-closed ? Fake providers; **no** live VPN) ? All tunnel kinds locate + spawn Go sidecars (READY/SOCKS) ? WireGuard + OpenVPN + Cisco + Fortinet + Azure VPN establish-path glue (`establish_wireguard` / `establish_openvpn` / `establish_cisco` / `establish_cisco_from_auth` / `establish_fortinet` / `establish_azure` / `establish_azure_from_entra` / `establish_watchguard` / `establish_watchguard_crv1` / `establish_watchguard_portal` / `establish_stormshield` / `establish_stormshield_sns`: config id ? metadata + secret/auth stub ? provider; Fake lookups + `FakeTunnelProvider` / `FakeEntraTokenProvider` / `FakeStormshieldSnsAuth`; **no** live WG/OpenVPN/ASA/FortiGate/Azure VPN/Firebox/SNS / local Cisco client / real SAML or Entra popup) ? WatchGuard / Stormshield / Azure VPN auth glue builds `OpenVpnSidecarConfig` from resolved materials ? WatchGuard Firebox username/password + optional OTP typing stub + establish glue (`providers::watchguard`; shared `wormhole-ovpnproxy`; **HTTP/SAML UI not wired**) ? Stormshield SNS auth stub (`StormshieldSnsAuth` + Fake; username/password + optional `password+otp` concat; **shared OpenVPN sidecar data plane**; establish glue via Fake ? **no** live SNS) ? OTP / second-factor prompt stub (`OtpPrompt` + Memory/Fake/Channel) + UI glue (`wormhole-ui` `OtpPromptChannel` / `FakeOtpPromptUi`; **no** GPUI dialog) ? Per-connect tunnel route prompt Fake glue (`wormhole-session` `resolve_tunnel_route` / `FakeTunnelRoutePromptUi`; `PromptBeforeTunnelConnect` off ? auto Direct/Tunnel; on ? AllowTunnel / PreferDirect / Cancel; Cancel fail-closed; **no** WinUI/GPUI dialog) ? Azure VPN Entra ID token stub (`EntraTokenProvider` + Memory/Fake; access token ? OpenVPN password / username `AzureAD`; refresh-token DPAPI cache glue (persist/load/clear; **no** WebView2); **interactive WebView2 popup not wired**) ? Fortinet SAML path stub (`SamlAuthFlow` ExternalBrowser/Embedded + Fake / `ChannelSamlAuthCallback`) + UI glue (`wormhole-ui` `SamlPromptChannel` / `FakeSamlPromptUi`; **no** live WebView2 / OS-browser) ? Cisco aggregate-auth stub (optional `group` + second-factor / Fake?Null OTP ? sidecar JSON; **no** STF/CSTP; **SAML SSO / CSD / client cert unsupported**) ? `Socks5Client` + `LocalForwarder` for RDP/VNC loopback bridge ? MCP loopback Streamable HTTP (`rmcp`) with bearer gate + approval stub ? MCP tools/list → capability report glue (`FakeMcpCapabilityServer`; loopback only; **no** live tools execution) ? MCP live SSH session registry Fake (`FakeMcpSessionRegistry` register/unregister Connected ids; **no** live MCP/SSH execution) → MCP tool approval gate Fake glue (`FakeMcpToolApprovalGlue` / `FakeMcpApprovalUi` Approve/Deny/Cancel before `execute_tool`; Connected-only when registry present; **no** live tool exec) → MCP clean-shutdown vs WebView2 flush ordering Fake glue (`FakeAppExitShutdownGlue` / `prepare_for_process_exit`; WebView/Bitwarden flush before MCP stop; **no** live WebView2/MCP HTTP)
**Audience:** agents wiring VPN / MCP into the Rust app composition root
**C# mirrors:** `Services/Tunneling/*`, `Services/Mcp/*`

---

## Crates

| Crate | Role |
|---|---|
| `wormhole-tunnels` | `TunnelManager` lease pool + providers; all kinds spawn Go sidecars |
| `wormhole-mcp` | Loopback Streamable HTTP MCP host (`rmcp` + axum); placeholder without `rmcp` |
| `wormhole-app` | `AppServices` `Arc<dyn Trait>` bag + `tracing` init |

Workspace members are listed in `rust/Cargo.toml`. Optional features keep builds green if a sibling is removed:

- `wormhole-tunnels`: `domain` (default) ? `wormhole-domain::TunnelKind`; `secrets` (default) ? `wormhole-secrets-win` for DPAPI cache reads
- `wormhole-mcp`: `rmcp` (default) ? official [`rmcp`](https://crates.io/crates/rmcp) `=3.0.1` with `transport-streamable-http-server`; `secrets` ? CredMgr token store
- `wormhole-app`: `domain` / `tunnels` / `mcp` (default on)

Storage / secrets crates are **not** required yet ? `wormhole-app` ships local `ConnectionStore` / `SecretStore` placeholders.

---

## TunnelManager semantics (parity with C#)

Matches `TunnelManager.cs` ? thin ref-counted lease glue (Fake providers OK; **no** live VPN required for unit tests):

1. **One live tunnel per `TunnelConfigId`** in a process-wide pool.
2. **`establish` returns a lease** (`TunnelLease`). Drop / `release` decrements the ref-count.
3. **Last release** evicts the pool entry and closes the underlying `TunnelInstance`.
4. **Concurrent establishes coalesce** ? joiners await the same shared provider future (one OTP / one sidecar spawn later). `FakeTunnelProvider::establish_count` stays at 1 under concurrent join.
5. **Stale / dead** entries are not reused ? next `establish` builds a fresh pool entry and provider call (**fail-closed**):
   - **Edited config:** `TunnelConfigSnapshot::updated_at` must match the snapshot stored on the pool entry (C# `TunnelConfig.UpdatedAt`). Tunnel-editor saves bump `UpdatedAt` even for payload-only edits; a mismatch evicts the pooled entry so new connections get the edited settings. Outstanding leases keep draining the pre-edit instance; the last release of that entry still closes it (C# `EditedConfig_GetsFreshTunnel_WhileOldLeasesDrain`).
   - **Dead tunnel:** instance state `Failed` or `Closed` (sidecar died) while owners have not released yet ? same eviction + fresh establish; old leases drain the dead instance.
6. **Secrets never in `Debug`/`Display`** ? manager / Fake provider Debug are counts + kinds only; establish errors must not echo `secret_blob` (see `manager_errors_never_echo_secret_blob` / `fake_provider_debug_omits_fail_next_message`).

### TunnelConfig storage (metadata)

SQLite `TunnelConfigs` rows are metadata only (`Id`, `Name`, `Kind`, `CreatedAt`, `UpdatedAt`) via `wormhole_storage::TunnelConfigRepository`. Secrets stay DPAPI under `%LOCALAPPDATA%\Wormhole\tunnels\` -> never in the DB. Blank / whitespace-only names are rejected at insert/update (`StorageError::InvalidArgument`).

`TunnelConfigRepository::update` persists caller-supplied `UpdatedAt` **verbatim** (does not stamp "now"). Editors must write Name/Kind with the old stamp, store the DPAPI payload, then bump `UpdatedAt` to publish invalidation ? otherwise a mid-save establish can cache the old payload under the new stamp. See [`03-storage.md`](03-storage.md) and C# `TunnelConfigRepository.UpdateAsync` / `EditTunnel_BumpsUpdatedAtOnlyAfterSecretIsStored`.

`TunnelConfigRepository::delete` is **fail-open** for in-use configs: it does not consult `Nodes.TunnelConfigId` (no FK). Matching C# `DeleteAsync`, the editor must refuse deletion while connections still reference the id (C# `TunnelConfigsViewModel.DeleteTunnelAsync` + partial index `IX_Nodes_TunnelConfigId`).

### Tunnel configs page / picker UI glue (`wormhole-ui`)

Lab-only metadata VMs mirroring C# `TunnelConfigsViewModel` list/filter/select and `TunnelPickerViewModel` picker subset — **no** DPAPI payload I/O, **no** GPUI chrome:

| Type | Role |
|---|---|
| `TunnelConfigRow` | Metadata row (`id` / `name` / `kind` / optional timestamps); sentinels use `kind=None` |
| `TunnelConfigSource` | `list_all()` trait — Fake in tests |
| `FakeTunnelConfigList` | In-memory catalog (`Debug` = len + fail flag only) |
| `StorageTunnelConfigSource` | `--features storage` → `TunnelConfigRepository::list_all` |
| `TunnelConfigsVm` | Configs page: load (replace snapshot; last-good on `Err`), search filter (name **or** kind display), `selected_config` for editor |
| `TunnelPickerVm` | Picker: inherit / no-tunnel sentinels (`INHERIT_TUNNEL_ID` / `NO_TUNNEL_ID`), repo load, stale `(missing tunnel …)` placeholder, `filter_tunnel_configs`, `resolve_tunnel_for_commit`, composes `TunnelUiState` |

```rust
use wormhole_ui::{
    FakeTunnelConfigList, TunnelConfigsVm, TunnelPickerVm, TunnelKind, tunnel_kind_display_name,
};
let mut page = TunnelConfigsVm::new();
page.load_from(&FakeTunnelConfigList::with_configs([/* rows */]))?;
let mut picker = TunnelPickerVm::new("(Inherit from folder)");
picker.load_from(&fake)?;
picker.load_from_node(Some(true), Some(config_id));
```

Non-goals: tunnel editor dialog, test dialog, add/edit/delete/test commands, DPAPI read/write, debounce (host-owned). See [adversarial-ledger-tunnel-configs-ui.md](adversarial-ledger-tunnel-configs-ui.md).

### Traits

```text
TunnelProvider::establish(config, secret) -> Arc<dyn TunnelInstance>
TunnelInstance::socks5_endpoint() -> Option<Socks5Endpoint>
TunnelInstance::bind_local_forwarder(host, port) -> local_port
  # 127.0.0.1:0 -> SOCKS5 -> host:port (RDP/VNC loopback bridge); reused per (host, port)
```

### SOCKS5 + local forwarder

Parity with C# `Socks5Client` / `LocalTcpForwarder` / `SocksTunnelInstance.BindLocalForwarderAsync`:

| Helper | Role |
|---|---|
| `Socks5Client::connect` | RFC 1928 no-auth CONNECT through sidecar `127.0.0.1:port` (IPv4/IPv6/DOMAINNAME + IDN Punycode; bracketed IPv6 accepted; non-no-auth methods rejected) |
| `LocalForwarder` | Bind **only** `127.0.0.1:0`, accept clients, bridge each via SOCKS5 to a fixed target; `shutdown`/`Drop` abort accept + in-flight bridges |
| `ForwarderRegistry` | Reuse one live listener per `(host, port)` for the shared tunnel lifetime (lock across bind; replace crashed listeners) |
| `validate_target` | Shared fail-closed check: reject empty/whitespace host and port `0` |
| `SidecarTunnelInstance` / `StubTunnelInstance` | Wire `bind_local_forwarder` when `Socks5Endpoint` is present |

SSH/SFTP consume `socks5_endpoint` directly; RDP/VNC use `bind_local_forwarder` because the ActiveX / RFB client opens its own socket.

**SSH route select (pure stub):** `wormhole_ssh::select_ssh_connect_target` /
`select_ssh_tunnel_route` maps resolved `TunnelEnabled` + optional lease SOCKS →
`SshConnectTarget::{Direct,Socks5}` (`FakeTunnelSocks`; fail-closed when tunnel on
without SOCKS / port `0`). **Serial never routes** (always Direct). Live SOCKS
CONNECT remains the transport hook. See [06-ssh-spike.md](06-ssh-spike.md) and
[adversarial-ledger-ssh-socks-route.md](adversarial-ledger-ssh-socks-route.md).
SFTP's parallel stub is `wormhole_sftp::select_sftp_transport`.

**Per-connect route prompt (Fake glue):** `wormhole_session::resolve_tunnel_route` /
`FakeTunnelRoutePromptUi` (+ optional `wormhole_ui::resolve_tunnel_route_from_settings`
mapping `AppSettings::prompt_before_tunnel_connect`). When the setting is off or
`tunnel_enabled` is false, returns the profile unchanged (auto Direct vs Tunnel). When
on and tunneled, Fake UI scripts `AllowTunnel` / `PreferDirect` / `Cancel`; Cancel and
missing prompt fail-closed (`Ok(None)` — abort connect). `PreferDirect` forces
`tunnel_enabled = false` for the attempt but keeps `tunnel_config_id`. Cosmetic tunnel
name lookup failures use `FALLBACK_TUNNEL_NAME` and never block the decision. Cooperative
`CancellationToken` aborts before/after prompt (`Err(Cancelled)`). **No** WinUI /
GPUI dialog. Orchestrator / tree Open wiring remains Pending — call
`resolve_tunnel_route` before tunnel establish in session VMs. See
[adversarial-ledger-tunnel-route-prompt.md](adversarial-ledger-tunnel-route-prompt.md).

**Physical network path / split-routing heuristics (Fake glue):** `wormhole_tunnels::FakePhysicalNetworkPath` /
`PhysicalNetworkPathProbe` + pure [`classify_split_route`](../../rust/crates/wormhole-tunnels/src/physical_network_path.rs)
(Direct / Physical / Unknown). Mirrors C# `WindowsPhysicalNetworkPathService` **spirit** for Stormshield
`TransportAdapterIds` preflight and per-host split-route hints — **no** live `dnsapi` / `iphlpapi` P/Invoke.
`get_best_path` filters VPN-like adapters, orders physical uplinks, caps at 8, and **does not** resolve
destination DNS (preflight must not re-enter VPN-captured resolvers). Empty / whitespace host →
`TunnelError::InvalidHost` (fail-closed). Public hosts default to `Unknown` without live probes.
Stormshield establish / portal HTTPS wiring remains Pending — supply `transport_adapter_ids` from Fake
path in unit tests. See [adversarial-ledger-physical-path.md](adversarial-ledger-physical-path.md).

### SidecarProcess (control plane)

`wormhole_tunnels::sidecar` owns path resolution + process supervision for the existing Go binaries (do **not** rewrite them):

| Helper | Role |
|---|---|
| `locate_sidecar` / `candidate_paths` | Search `WORMHOLE_SIDECAR_DIR`, app-relative dir (C# `AppPaths`), `bin/`, `tools/<name>/`, `obj/wgproxy/<arch>/` |
| `validate_sidecar_dir` | Trust boundary for `WORMHOLE_SIDECAR_DIR`: reject NUL and `..` components |
| `SidecarProcess` | Spawn, write one stdin config line (keep stdin open), bounded stdout `READY`/`SOCKS` parse, stderr drain, kill-on-drop, shutdown via stdin EOF |
| `SidecarTunnelInstance` | `TunnelInstance` wrapper over a live process + SOCKS endpoint |
| `parse_ready_or_socks_line` | Pure handshake-line parser (digits-only port; max 64 bytes; no Docker) |

Missing binary -> [`TunnelError::BinaryNotFound`] (clear error). **Never** pretend `Up` / Connected without a READY/SOCKS handshake. Stdin config JSON is never logged.

### Providers

| Kind | Status | Binary / project | `secret_blob` stdin shape |
|---|---|---|---|
| **WireGuard** | **Wired** + **establish-path glue stub** | `tools/wormhole-wgproxy` | WireGuard sidecar JSON |
| **OpenVPN** | **Wired** + **establish-path glue stub** | `tools/wormhole-ovpnproxy` | `OpenVpnSidecarConfig` (`profile_ovpn`, ?) |
| **Fortinet** | **Wired** (sidecar) + **SAML path stub** + **Channel UI glue** + **establish-path glue stub** | `tools/wormhole-fortiproxy` | Fortinet sidecar JSON; SAML `auth_id` / `SVPNCOOKIE` via Fake / Channel prompt (stdin when establish resolves) |
| **WatchGuard** | **Wired** (ovpn data plane) + **Firebox auth stub** + **establish-path glue stub** | `tools/wormhole-ovpnproxy` (shared; **no** WatchGuard-specific binary) | Same as OpenVPN -> build via `auth_glue` / `providers::watchguard` (not raw `WatchguardSettings`) |
| **Stormshield** | **Wired** (ovpn data plane) + **SNS auth stub** + **establish-path glue stub** | `tools/wormhole-ovpnproxy` | Same as OpenVPN -> build via `auth_glue` / `StormshieldSnsAuth` (`password+otp`; not portal settings JSON) |
| **Azure VPN** | **Wired** (ovpn data plane) + **Entra token stub** + **establish-path glue stub** | `tools/wormhole-ovpnproxy` | Same as OpenVPN (`username`=`AzureAD`, password=access token) via `auth_glue` / `EntraTokenProvider` |
| **Cisco Secure Client** | **Wired** (sidecar) + **aggregate-auth stub** + **establish-path glue stub** | `tools/wormhole-ciscoproxy` | `CiscoSecureClientSidecarConfig` (optional `group` / `secondary_password` / `totp_secret`); **no** SAML SSO / CSD / client certs |

#### WireGuard establish-path glue (`providers::wireguard::establish`)

Thin load→establish stub (no live WireGuard interface):

| Helper | Role |
|---|---|
| `establish_wireguard(config_id, configs, secrets, provider)` | Load metadata + secret → shape-gate → `TunnelProvider::establish` |
| `TunnelConfigLookup` / `FakeTunnelConfigLookup` | Metadata by id (production: wrap `wormhole_storage::TunnelConfigRepository`) |
| `TunnelSecretLookup` / `FakeTunnelSecretLookup` | Secret blob by id; `PayloadStoreSecretLookup<S: TunnelPayloadStore>` adapts existing DPAPI/`FakeTunnelPayloadStore` (feature `secrets`) — do **not** duplicate stores |
| `FAKE_WIREGUARD_SIDECAR_JSON` | Same `interface_private_key` sidecar JSON shape already used in crate tests |
| Fail-closed | Missing config → `ConfigNotFound`; missing secret → `SecretMissing`; wrong kind → `WrongKind`; empty / PascalCase / whitespace-key / invalid JSON → `Establish` (**never** echoes secret). `Debug` on Fake secret lookup is length-only. |

Unit tests drive `FakeTunnelProvider` / a capturing test double — **not** a real `wg` device or network. See [`adversarial-ledger-wireguard-establish.md`](adversarial-ledger-wireguard-establish.md).

#### OpenVPN establish-path glue (`providers::openvpn::establish`)

Thin load->establish stub (**separate** API from WireGuard; shared lookup traits / Fake stores; no live OpenVPN process):

| Helper | Role |
|---|---|
| `establish_openvpn(config_id, configs, secrets, provider)` | Load metadata + secret -> `profile_ovpn` shape-gate -> `TunnelProvider::establish` |
| Lookups | Reuses `TunnelConfigLookup` / `TunnelSecretLookup` / Fakes / `PayloadStoreSecretLookup` from the WireGuard establish module (same SQLite + DPAPI stores) |
| `FAKE_OPENVPN_SIDECAR_JSON` | Same `profile_ovpn` sidecar JSON shape already used in crate tests |
| Fail-closed | Same as WireGuard (`ConfigNotFound` / `SecretMissing` / `WrongKind` / `Establish`); empty / whitespace `profile_ovpn` (even with `mock:true`), PascalCase editor blobs, and invalid JSON reject before provider; secret never in `Debug` / logs / error text |

Unit tests drive `FakeTunnelProvider` / a capturing test double -- **not** `wormhole-ovpnproxy` / network. See [adversarial-ledger-openvpn-establish.md](adversarial-ledger-openvpn-establish.md).

#### WatchGuard establish-path glue (`providers::watchguard::establish`)

Thin load->establish stub (**separate** from WireGuard / OpenVPN / Cisco / Fortinet / Azure / Stormshield; shared lookup traits / Fake stores; **no** live Firebox / network):

| Helper | Role |
|---|---|
| `establish_watchguard(config_id, configs, secrets, provider)` | Load metadata + already-resolved OpenVPN sidecar secret -> shape-gate -> `TunnelProvider::establish` |
| `establish_watchguard_crv1(...)` | Load metadata -> `resolve_firebox_crv1_sidecar_json` (FakeFireboxCredentials + optional Fake/Null OTP) -> establish |
| `establish_watchguard_portal(...)` | Load metadata -> `resolve_firebox_portal_sidecar_json` (OTP->password quirk) -> establish |
| Lookups | Reuses `TunnelConfigLookup` / `TunnelSecretLookup` / Fakes / `PayloadStoreSecretLookup` from the WireGuard establish module |
| `FAKE_WATCHGUARD_SIDECAR_JSON` / `FAKE_WATCHGUARD_PROFILE_OVPN` | Minimal OpenVPN sidecar JSON / profile fragment for Fake establish tests |
| Fail-closed | Missing config -> `ConfigNotFound`; missing secret -> `SecretMissing`; wrong kind -> `WrongKind`; editor settings blob / empty / whitespace `profile_ovpn` / invalid JSON / empty Firebox username/password -> `Establish` (**never** echoes secret). Null OTP on CRV1 **and** portal -> `Cancelled` |

Unit tests drive `FakeTunnelProvider` / recording Fake (stdin capture for CRV1 `challenge_response` vs portal OTP→password) — **not** `wormhole-ovpnproxy` / live Firebox. Portal HTTP / SAML UI remain unwired (caller supplies profile text). See [adversarial-ledger-watchguard-establish.md](adversarial-ledger-watchguard-establish.md).

#### Stormshield SNS establish-path glue (`providers::stormshield::establish`)

Thin load->establish stub (**separate** module from WatchGuard / Fortinet / Azure; shared lookup traits / Fake stores; **no** live SNS portal / network):

| Helper | Role |
|---|---|
| `establish_stormshield(config_id, configs, secrets, provider)` | Load metadata + already-resolved OpenVPN sidecar secret -> shape-gate -> `TunnelProvider::establish` |
| `establish_stormshield_sns(...)` | Load metadata -> `StormshieldSnsAuth` (Fake/Null) + `stormshield_materials_from_sns` / `stormshield_sns_to_sidecar_json` (`password+otp`) -> establish |
| Lookups | Reuses `TunnelConfigLookup` / `TunnelSecretLookup` / Fakes / `PayloadStoreSecretLookup` from the WireGuard establish module (production: `TunnelConfigRepository` + DPAPI) |
| `FAKE_STORMSHIELD_SIDECAR_JSON` / `FAKE_STORMSHIELD_PROFILE_OVPN` | Minimal OpenVPN sidecar JSON / profile fragment for Fake establish tests |
| Fail-closed | Missing config -> `ConfigNotFound`; missing secret -> `SecretMissing`; wrong kind -> `WrongKind`; editor settings blob / empty -> `Establish` (**never** echoes secret). Empty/whitespace profile on SNS path fails **before** auth (OTP not spent). Null SNS auth on OTP spend (`DataPlane` / `PortalDownload`) -> `Cancelled` |

Unit tests drive `FakeTunnelProvider` + `FakeStormshieldSnsAuth` -- **not** `wormhole-ovpnproxy` / live SNS. Portal download / config-hash cache / SSO UI remain unwired (caller supplies profile text). See [adversarial-ledger-stormshield-establish.md](adversarial-ledger-stormshield-establish.md).

#### Cisco Secure Client establish-path glue (`providers::cisco::establish`)

Thin load→establish stub (**separate** from WireGuard / OpenVPN / Fortinet; shared lookup traits / Fake stores; **no** live ASA / local Cisco client):

| Helper | Role |
|---|---|
| `establish_cisco(config_id, configs, secrets, provider)` | Load metadata + secret → `host` shape-gate → `TunnelProvider::establish` |
| `establish_cisco_from_auth(config_id, configs, options, prompt, provider)` | Load metadata → `prepare_cisco_sidecar_config` (aggregate-auth / Fake·Null OTP) → establish |
| Lookups | Reuses `TunnelConfigLookup` / `TunnelSecretLookup` / Fakes / `PayloadStoreSecretLookup` from the WireGuard establish module |
| `FAKE_CISCO_SIDECAR_JSON` | Minimal snake_case `host` sidecar JSON for Fake establish tests |
| `reject_cisco_unsupported_auth` | Fail-closed SAML SSO / CSD / client cert (same as `reject_unsupported_cisco_auth`) |
| Fail-closed | Missing config → `ConfigNotFound`; missing secret → `SecretMissing`; wrong kind → `WrongKind`; empty / whitespace `host` / PascalCase editor blob → `Establish` (**never** echoes secret). Empty credentials / missing `OtpPrompt` → `Establish`; Null OTP → `Cancelled` |

Unit tests drive `FakeTunnelProvider` — **not** `wormhole-ciscoproxy` / ASA / installed Cisco client. `CiscoSecureClientProvider::establish` still takes already-resolved stdin JSON (prepare is not inside the provider).

#### Fortinet establish-path glue (`providers::fortinet::establish`)

Thin load?auth?establish stub (**separate** module from WireGuard / OpenVPN / Cisco; **no** live FortiGate / network / real SAML browser):

| Helper | Role |
|---|---|
| `establish_fortinet(config_id, configs, secrets, provider, saml)` | Load metadata + `FortinetSettings` DPAPI blob -> optional SAML stub -> sidecar JSON -> `TunnelProvider::establish` |
| `FortinetConfigLookup` / `FakeFortinetConfigLookup` | Metadata by id (production: wrap `TunnelConfigRepository`) -> Fortinet-local traits (not shared with WG/OpenVPN) |
| `FortinetSecretLookup` / `FakeFortinetSecretLookup` / `FortinetPayloadStoreSecretLookup` | Secret blob by id; adapts `TunnelPayloadStore` when feature `secrets` |
| `parse_fortinet_settings` / `build_fortinet_sidecar_config` / `resolve_fortinet_sidecar_json` | PascalCase editor JSON -> snake_case sidecar; SAML via `FakeSamlAuthCallback` / `StubSamlAuthCallback` / `ChannelSamlAuthCallback` |
| `FAKE_FORTINET_SETTINGS_JSON` / `FAKE_FORTINET_SIDECAR_JSON` | Editor settings / sidecar shapes for Fake tests |
| Fail-closed | Missing config -> `ConfigNotFound`; missing secret -> `SecretMissing`; wrong kind -> `WrongKind`; empty Host / missing user+pass / external+realm / embedded+pin -> `Establish`; Stub SAML -> `NotImplemented`; Channel cancel / auto-cancel / abandon -> `Cancelled`. Password / TOTP / `auth_id` / `SVPNCOOKIE` never in `Debug` / logs / errors |

Unit tests drive `FakeTunnelProvider` + Fake / Channel SAML -> **not** `wormhole-fortiproxy` / FortiGate. WebView2 / OS-browser SAML remain unwired (Channel is Fake UI transport only).

#### Azure VPN establish-path glue (`providers::azure_vpn::establish`)

Thin load → Entra → establish stub (**separate** module from WireGuard / OpenVPN / Cisco / Fortinet / WatchGuard; shared lookup traits / Fake stores; **no** live Azure VPN / Entra popup):

| Helper | Role |
|---|---|
| `establish_azure(config_id, configs, secrets, provider)` | Load metadata + already-resolved OpenVPN sidecar secret → `profile_ovpn` shape-gate → `TunnelProvider::establish` |
| `establish_azure_from_entra(config_id, configs, options, entra, provider)` | Load metadata → `request_entra_access_token` (Fake/Null Entra) → `AzureVpnAuthGlue` stdin JSON → shape-gate → establish |
| `AzureVpnEstablishOptions` | Non-secret profile + tenant / audience / client_id; `Debug` redacts `profile_ovpn` |
| Lookups | Reuses `TunnelConfigLookup` / `TunnelSecretLookup` / Fakes / `PayloadStoreSecretLookup` from the WireGuard establish module (production: `TunnelConfigRepository` + DPAPI store) |
| `FAKE_AZURE_VPN_SIDECAR_JSON` | Minimal OpenVPN sidecar JSON with `username`=`AzureAD` for Fake establish tests |
| Fail-closed | Missing config → `ConfigNotFound`; missing secret → `SecretMissing`; wrong kind → `WrongKind`; empty profile / empty token / empty secret → `Establish`; Null Entra → `Cancelled`. Tokens / secrets never in `Debug` / logs / errors |

Unit tests drive `FakeTunnelProvider` + `FakeEntraTokenProvider` → **not** `wormhole-ovpnproxy` / Azure Gateway / Microsoft sign-in popup. Establish-path glue does **not** write the refresh-token tokencache; interactive WebView2 remains unwired. `AzureVpnProvider::establish` still takes already-resolved stdin JSON (Entra prepare is not inside the provider). Adversarial ledger: [adversarial-ledger-azure-establish.md](adversarial-ledger-azure-establish.md).

#### Auth / profile glue (`providers::auth_glue`)

C# WatchGuard / Stormshield / Azure providers turn editor settings + OTP / SAML / Entra into `OpenVpnSidecarConfig` **before** spawning ovpnproxy. Rust now has the **construction** half:

| Helper | Role |
|---|---|
| `OpenVpnSidecarConfig` / `to_stdin_json` | Snake_case wire type; validates non-empty `profile_ovpn` |
| `OvpnAuthGlue` + `WatchguardAuthGlue` / `StormshieldAuthGlue` / `AzureVpnAuthGlue` | Trait hooks -> stdin JSON |
| `ResolvedOvpnMaterials` / `azure_materials_from_access_token` / `azure_materials_from_entra` / `watchguard_materials` / `stormshield_materials` | Post-auth inputs |
| Cache decode + `try_read_*_cache` / `AzureVpnRefreshTokenCache` | WatchGuard / Stormshield `*.ovpncache` and Azure `*.tokencache` (DPAPI + `tunnel_id_entropy` when feature `secrets`; Azure persist/load/clear via confined secrets-win store) |

- Passing DPAPI-stored **editor** settings JSON straight to these providers still fails the shape gate (missing `profile_ovpn`).
- **Fail closed:** WatchGuard / Stormshield / Azure / OpenVPN `establish` requires valid JSON with non-empty snake_case `profile_ovpn` before spawn. Constructed configs from `auth_glue` pass that gate. Errors never echo the secret blob.
- `Debug` for `OpenVpnSidecarConfig` / `ResolvedOvpnMaterials` / cache records redacts profile, password, challenge, and refresh token (`[REDACTED]`).
- Azure glue forces `username` = `AzureAD` even if callers supply another value.
- **OTP / second-factor prompt stub** (`auth_glue::otp_prompt`, mirrors C# `IOtpPromptService`):
  - Traits: `OtpPrompt` / `SecondFactorPrompt` (same contract); hook helpers `request_otp` / `request_second_factor` (trim, reject empty, map user dismiss -> `TunnelError::Cancelled`).
  - Test / headless: `MemoryOtpPrompt` / `FakeOtpPrompt` (scripted queue), `NullOtpPrompt` (always cancel), `ChannelOtpPrompt` (oneshot channel for UI glue).
  - `OtpCode` redacts via `Debug`/`Display`; `OtpPromptResponse` / `MemoryOtpPrompt` redact via `Debug` (`[REDACTED]`); never log OTP values.
  - **UI glue** (`wormhole-ui` feature `tunnels`, `otp_prompt` module - mirrors C# `DialogOtpPromptService` **transport** only, **no** GPUI / ContentDialog chrome):
    - `OtpPromptChannel::open` -> provider `SharedOtpPrompt` + pending `mpsc` receiver. Join pattern: `shared()` + spawn/`request_otp`, answer via `pending_rx` / `FakeOtpPromptUi` (no `&self` async helpers on the channel — those would conflict with `&mut` pending drain).
    - `FakeOtpPromptUi` / `FakePrompt` answers pending prompts (submit / cancel); `submit_pending` / `cancel_pending` helpers.
    - Cancel / Fake `None` / exhausted script / pending or channel abandon -> `TunnelError::Cancelled` (fail closed). Submitted empty / whitespace-only -> `TunnelError::Establish` (never echoes the code; C# dialog disables Submit on whitespace). `FakeOtpPromptUi` `Debug` redacts queued codes.
    - Adversarial ledger: [adversarial-ledger-otp-ui.md](adversarial-ledger-otp-ui.md).
- **TLS trust prompt stub** (`auth_glue::tls_trust_prompt`, mirrors C# `ITlsTrustPromptService`):
  - Trait: `TlsTrustPrompt`; hook `request_tls_trust` (AcceptOnce → `Ok(true)`; Reject / dismiss → `TunnelError::Cancelled` fail-closed).
  - Test / headless: `MemoryTlsTrustPrompt` / `FakeTlsTrustPrompt` (scripted `TlsTrustChoice` queue), `NullTlsTrustPrompt` (always reject), `ChannelTlsTrustPrompt` (oneshot channel for UI glue).
  - `TlsTrustPromptRequest` `Debug` uses title/message lengths + fingerprint prefix (8 chars max); tracing uses the same — never full thumbprints or message bodies.
  - Accept button label constant `ACCEPT_BUTTON_LABEL` = `"Trust and connect"` (C# parity).
  - **UI glue** (`wormhole-ui` feature `tunnels`, `tls_trust_prompt` module — mirrors C# `DialogTlsTrustPromptService` **transport** only, **no** GPUI / ContentDialog chrome):
    - `TlsTrustPromptChannel::open` → provider `SharedTlsTrustPrompt` + pending `mpsc` receiver. Join pattern: `shared()` + spawn/`request_tls_trust`, answer via `pending_rx` / `FakeTlsTrustPromptUi`.
    - `FakeTlsTrustPromptUi` scripts AcceptOnce / Reject; `accept_tls_trust_pending` / `reject_tls_trust_pending` helpers.
    - Reject / exhausted script / pending or channel abandon → `TunnelError::Cancelled` (fail closed). `FakeTlsTrustPromptUi` `Debug` uses fingerprint prefix + lengths only.
    - Adversarial ledger: [adversarial-ledger-tls-trust-prompt.md](adversarial-ledger-tls-trust-prompt.md).
  - **Not wired:** Stormshield portal TLS consent loops (`ConfirmTrustAsync` / persist `TrustServerCertificate`) — call `request_tls_trust` when portal establish lands.
  - **Not wired into WatchGuard / Stormshield / Fortinet portal loops yet** - those paths should call `request_otp` when ported. Cisco aggregate-auth prepare (`prepare_cisco_sidecar_config` + `CiscoSecondFactor::Prompt`) already calls `request_second_factor` (Fake / Null / Channel). Sidecar `establish` still takes already-resolved stdin JSON and does not prompt. Interactive Entra WebView2 **UI** remains TODO. Fortinet SAML has path types + Fake / Channel callback + **UI glue** (see below) — **not** full WebView2 / OS-browser.
- **WatchGuard Firebox username/password + optional OTP stub** (`providers::watchguard::firebox_auth`, mirrors C# credential / CRV1 + portal password quirk):
  - Typed helpers: `FireboxUsername` / `FireboxPassword` / `FireboxCredentials` / `FireboxSecondFactor` (`OneTimeCode` | `Push`); `"p"` -> Push via `normalize_firebox_second_factor`.
  - Reuses `auth_glue::request_otp` / `request_second_factor` through `request_firebox_second_factor`; `NullOtpPrompt` / cancel -> `TunnelError::Cancelled` on `resolve_firebox_*` (fail-closed).
  - **Field fork (do not cross):** CRV1 / stored-profile -> OTP in `challenge_response`, account password stays on `password`; portal sslvpn_logon -> OTP becomes OpenVPN `password` (`portal_openvpn_password`), push keeps account password, **no** `challenge_response`.
  - Test / headless: `FakeFireboxCredentials` (+ `FakeOtpPrompt`); `resolve_firebox_*_sidecar_json` end-to-end to stdin JSON. `FireboxPassword` redacts via `Debug`/`Display`; OTP / `FireboxSecondFactor` / Fake redact via `Debug` (`[REDACTED]`).
  - **Data plane is the shared OpenVPN sidecar** (`wormhole-ovpnproxy`) -> same binary as OpenVPN / Stormshield / Azure VPN. Establish-path glue (`establish_watchguard` / `_crv1` / `_portal`) loads metadata + secret/auth stubs then calls Fake/`WatchguardProvider` (**Firebox HTTP / SAML UI not wired**; profile text is caller-supplied).
- **Stormshield SNS username/password + optional OTP stub** (`auth_glue::stormshield_sns`, mirrors C# `StormshieldTunnelProvider` / `StormshieldSettings`):
  - Typed helpers: `StormshieldUsername` / `StormshieldPassword` / `StormshieldSnsCredentials` / `StormshieldSnsAuthResult` / `StormshieldOtpSpend` (`None` | `DataPlane` | `PortalDownload`).
  - OTP composition is **`password + otp`** via `compose_sns_auth_password` / `append_otp_to_password` (portal `pass` and OpenVPN `auth-user-pass`) -> **not** WatchGuard CRV1 `challenge_response`.
  - Hook: `request_stormshield_otp` / `resolve_sns_data_plane_auth` (C#-parity title `"Stormshield OTP -> {name}"`); materials -> `stormshield_materials_from_sns` / `stormshield_sns_to_sidecar_json`.
  - Test / headless: `MemoryStormshieldSnsAuth` / `FakeStormshieldSnsAuth` (deterministic OTP queue), `NullStormshieldSnsAuth` (fail-closed cancel when OTP spend required).
  - `StormshieldPassword` / credentials / auth result / Fake redact via `Debug`/`Display` (`[REDACTED]`); never log password or OTP.
  - **Data plane is the shared OpenVPN sidecar** (`wormhole-ovpnproxy`) -> same binary as OpenVPN / WatchGuard / Azure VPN; **no** Stormshield-specific binary. Portal download / config-hash cache / OTP reuse guard / SSO **UI not wired**. Establish-path glue (`establish_stormshield` / `establish_stormshield_sns`) wires config id + secret **or** profile + SNS auth Fake â†’ `FakeTunnelProvider` / production `StormshieldProvider`; **`StormshieldProvider::establish` still expects already-resolved OpenVPN sidecar JSON**.
- **Azure VPN Entra ID token stub** (`auth_glue::entra_token`, mirrors C# `IAzureVpnAuthService` / `AzureVpnTokenResult` / cache path):
  - Trait: `EntraTokenProvider`; hook `request_entra_access_token` (trim, reject empty access token, map user dismiss -> `TunnelError::Cancelled`; returns **access only** ? refresh discarded here; persist via `persist_entra_refresh_token` / `AzureVpnRefreshTokenCache`).
  - **OpenVPN credential contract:** username = `AzureAD` (`AZURE_AAD_USERNAME` / `ENTRA_OPENVPN_USERNAME`); password = Entra **access** token. Helper `azure_materials_from_entra` -> `ResolvedOvpnMaterials` for `AzureVpnAuthGlue`.
  - Test / headless: `MemoryEntraTokenProvider` / `FakeEntraTokenProvider` (scripted queue), `NullEntraTokenProvider` (always cancel).
  - Refresh-token cache glue (`auth_glue::entra_refresh_cache`, mirrors C# `IAzureVpnTokenCache`): `AzureVpnRefreshTokenCache` + `FakeAzureVpnRefreshTokenCache` / `DpapiAzureVpnRefreshTokenCache` (feature `secrets`). Persist / load / clear under `%LOCALAPPDATA%\Wormhole\azurevpn-cache\<id:N>.tokencache` via confined `wormhole-secrets-win::AzureVpnTokenCacheStore` (tunnel-id entropy, atomic write; **not** keys/tunnels stores). Identity hash + 90-day max-age; clear on logout (`clear_entra_refresh_token_cache`). Path escape fail-closed. **No interactive WebView2 / WinRT popup.** Cache JSON encode/decode in `auth_glue::cache`.
  - `AccessToken` / `RefreshToken` redact via `Debug`/`Display`; `EntraTokenResult` / `EntraTokenResponse` / `MemoryEntraTokenProvider` / Fake cache redact via `Debug` (`[REDACTED]`); never log tokens.
  - Establish-path glue (`establish_azure` / `establish_azure_from_entra`) wires config id + secret **or** profile + Entra stub -> `FakeTunnelProvider` / production `AzureVpnProvider`; **`AzureVpnProvider::establish` still expects already-resolved OpenVPN sidecar JSON**. Interactive Microsoft sign-in popup remains TODO.
- **Fortinet SAML SSO stub** (`providers::fortinet::saml`, mirrors C# `IFortinetSamlAuthService` / `FortinetSamlAuthResult`):
  - `SamlAuthFlow::ExternalBrowser { callback_port }` (default [`DEFAULT_SAML_REDIRECT_PORT`] = **8020**) vs `SamlAuthFlow::Embedded` (cookie path).
  - Ephemeral results: `SamlAuthResult::AuthId` / `SamlAuthResult::SvpnCookie` (`SamlAuthId` / `SvpnCookie` redact via `Debug`/`Display`; never log `SVPNCOOKIE` / `auth_id`).
  - `SamlAuthCallback` + `authenticate_fortinet_saml` validate port / flow→credential match; `StubSamlAuthCallback` -> `NotImplemented`; tests use `FakeSamlAuthCallback` (scripted ephemeral tokens); UI transport uses `ChannelSamlAuthCallback` + `SamlPromptResponse` / `PendingSamlPrompt` (oneshot; auto-cancel until `open_channel`).
  - **UI glue** (`wormhole-ui` feature `tunnels`, `saml_prompt` module — **transport only**, **no** WebView2 / GPUI / OS-browser):
    - `SamlPromptChannel::open` -> provider `SharedSamlAuthCallback` + pending `mpsc` receiver. Join: `shared()` + spawn/`authenticate` / `establish_fortinet`, answer via `pending_rx` / `FakeSamlPromptUi`.
    - `FakeSamlPromptUi` answers pending prompts (`auth_id` / `SVPNCOOKIE` / cancel); `submit_auth_id` / `submit_svpn_cookie` / `submit_saml_result` / `cancel_pending_saml` helpers.
    - Cancel / Fake `None` / exhausted script / pending or channel abandon -> `SamlAuthError::Cancelled` / `ChannelClosed` -> establish `TunnelError::Cancelled` (fail closed). Empty / wrong-kind submit -> `InvalidResult` (never echoes tokens). External+realm / embedded+pin still rejected **before** the prompt. `FakeSamlPromptUi` / `SamlPromptResponse` `Debug` redacts queued tokens.
  - **Not full WebView2 or OS external-browser loopback yet** -> no listener bind, no browser launch. Establish-path glue (`establish_fortinet`) calls the SAML callback when `UseSingleSignOn`; `FortinetProvider::establish` still takes already-resolved sidecar JSON.
- **Cisco aggregate-auth stub** (`providers::cisco::aggregate_auth`, mirrors C# / Go `CiscoSecureClientSidecarConfig` + `answerForm`):
  - `CiscoAuthOptions` with optional `group` + [`CiscoSecondFactor`] (`None` / `SecondaryPassword` / `TotpSecret` / `Prompt`).
  - `prepare_cisco_sidecar_config` -> `CiscoSecureClientSidecarConfig` stdin JSON (shape-gated `host`); `Prompt` uses existing Fake / Null / Channel `OtpPrompt`.
  - Pure `answer_aggregate_auth_form` typing (primary vs challenge; `secondary_password`-named fields on primary) -> **no** HTTPS aggregate-auth, **no** STF / CSTP.
  - **Unsupported (v1):** SAML SSO, client certificates, CSD / HostScan (`reject_unsupported_cisco_auth` / `reject_cisco_unsupported_auth`).
  - `Debug` redacts password / secondary password / TOTP secret / form answers (`[REDACTED]`); never log secrets or stdin JSON.
  - Establish-path glue (`establish_cisco` / `establish_cisco_from_auth`) wires config id + secret **or** auth stub -> `FakeTunnelProvider` / production provider; **`CiscoSecureClientProvider::establish` still expects already-resolved sidecar JSON** (no prepare inside the provider).
- Adversarial ledgers: [adversarial-ledger-crypto-auth.md](adversarial-ledger-crypto-auth.md) (auth glue / cache), [adversarial-ledger-otp-prompt.md](adversarial-ledger-otp-prompt.md) (OTP prompt stub), [adversarial-ledger-otp-ui.md](adversarial-ledger-otp-ui.md) (OTP prompt UI glue in `wormhole-ui`; **no** GPUI dialog), [adversarial-ledger-tls-trust-prompt.md](adversarial-ledger-tls-trust-prompt.md) (TLS trust prompt Fake glue in `wormhole-tunnels` + `wormhole-ui`; **no** GPUI dialog / live TLS), [adversarial-ledger-tunnel-route-prompt.md](adversarial-ledger-tunnel-route-prompt.md) (per-connect tunnel route prompt Fake glue in `wormhole-session`; **no** WinUI/GPUI dialog), [adversarial-ledger-physical-path.md](adversarial-ledger-physical-path.md) (physical network path / split-routing Fake glue in `wormhole-tunnels`; **no** live `dnsapi`/`iphlpapi`), [adversarial-ledger-watchguard-auth.md](adversarial-ledger-watchguard-auth.md) (WatchGuard Firebox auth stub; shared ovpnproxy; **HTTP/SAML UI not wired**), [adversarial-ledger-watchguard-establish.md](adversarial-ledger-watchguard-establish.md) (WatchGuard establish-path glue; FakeTunnel / Firebox auth stubs; **no** live Firebox), [adversarial-ledger-stormshield-auth.md](adversarial-ledger-stormshield-auth.md) (Stormshield SNS auth stub; shared `wormhole-ovpnproxy`; **UI not wired**), [adversarial-ledger-stormshield-establish.md](adversarial-ledger-stormshield-establish.md) (Stormshield SNS establish-path glue; FakeTunnel / Fake SNS; **no** live SNS), [adversarial-ledger-entra-token.md](adversarial-ledger-entra-token.md) (Entra token stub; **interactive WebView2 popup not wired**), [adversarial-ledger-entra-token-cache.md](adversarial-ledger-entra-token-cache.md) (Entra refresh-token DPAPI cache glue; confined `azurevpn-cache`; **no** live Entra), [adversarial-ledger-azure-establish.md](adversarial-ledger-azure-establish.md) (Azure VPN establish-path glue; FakeTunnel / FakeEntra; **no** live Azure / Entra popup), [adversarial-ledger-fortinet-saml.md](adversarial-ledger-fortinet-saml.md) (Fortinet SAML stub), [adversarial-ledger-fortinet-saml-ui.md](adversarial-ledger-fortinet-saml-ui.md) (Fortinet SAML prompt UI glue in `wormhole-ui`; **no** WebView2 / OS-browser), [adversarial-ledger-fortinet-establish.md](adversarial-ledger-fortinet-establish.md) (Fortinet establish-path glue; FakeTunnel / Fake SAML; **no** live FortiGate), [adversarial-ledger-wireguard-establish.md](adversarial-ledger-wireguard-establish.md) (WireGuard establish-path glue; FakeTunnel / PayloadStoreSecretLookup; **no** live WG), [adversarial-ledger-openvpn-establish.md](adversarial-ledger-openvpn-establish.md) (OpenVPN establish-path glue; **no** live ovpnproxy), [adversarial-ledger-cisco-auth.md](adversarial-ledger-cisco-auth.md) (Cisco aggregate-auth stub; **no** STF/CSTP; **SAML SSO / CSD / client cert unsupported**), [adversarial-ledger-cisco-establish.md](adversarial-ledger-cisco-establish.md) (Cisco establish-path glue; **no** live ASA).

Unit tests that need a successful establish without a real VPN use `FakeTunnelProvider` (in-memory `StubTunnelInstance`) or the package binary `fake-tunnel-sidecar` (prints `READY 18765`; flags `--hang` / `--oversized` / `--bad-ready` / `--stderr-flood` / `--delay-ready` for negative paths).

Helpers: `wormhole_tunnels::sidecar::{sidecar_relative_path, sidecar_binary_name, SidecarBinary, validate_sidecar_dir, ?}`.

### Cancellation

Dropping an in-flight `TunnelManager::establish` future releases that caller's pool ref (parity with C# `WaitAsync` cancellation + `ReleaseAsync`). The last waiter marks the entry cancelled; an orphaned provider result is closed and not pooled. (`EstablishRefGuard` + coalesce behavior preserved.)

Last-lease `release_entry` holds the **pool lock then entry lock** (same order as `acquire_entry`) across the zero-ref transition and eviction so a concurrent `establish` cannot resurrect a half-released entry and receive a closing instance. Acquire also refuses `ref_count == 0` / `cancelled` as defense in depth. Partial cancel (one of N coalesce waiters aborts) leaves the shared establish running for survivors.

Adversarial lease ledger: [adversarial-ledger-tunnel-lease.md](adversarial-ledger-tunnel-lease.md).

### Tests

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

- Lease / coalesce / one-OTP / last-close / `updated_at` bump (pooled + in-flight) / dead `Failed`/`Closed` fresh establish / last-release×establish race / partial cancel / secret-safe Debug: `crates/wormhole-tunnels/tests/lease_coalesce.rs`
- READY/SOCKS parse, missing binary, fake-sidecar handshake (all kinds), OpenVPN/Fortinet hang (not Up + secret absent), OpenVPN coalesce: `tests/sidecar_control_plane.rs`
- SOCKS5 client + local forwarder (echo + mock SOCKS): unit tests in `src/socks5.rs` / `src/forwarder.rs`; reuse via `lease_coalesce`
- No Docker required for unit/integration tests in this crate.

---

## MCP host (parity with C#)

C# binds Kestrel to **loopback only** (`http://127.0.0.1:{port}`, default **8765**), Streamable HTTP, bearer token in Credential Manager.

Rust (`wormhole-mcp`, feature `rmcp` default-on):

| Piece | Behavior |
|---|---|
| `RmcpLoopbackHost` | Binds **`127.0.0.1` only** via `axum` + `rmcp::StreamableHttpService`; rejects non-loopback bind addresses and non-loopback peers |
| Bind helpers | `validate_loopback_bind` / `parse_loopback_bind` / `validate_loopback_host` fail-closed on `0.0.0.0`, `[::]`, LAN, link-local, public, **all** IPv4-mapped forms (including `::ffff:127.0.0.1`), and scoped IPv6 loopback (`[::1%1]`); peer checks still accept mapped loopback via `is_loopback_ip`; post-bind `ensure_bound_loopback` |
| Port `0` | Rejected at construction (`validate_mcp_port` / `InvalidPort`) |
| Bearer auth | Gate on every route (`Authorization: Bearer ?`); token never written to tracing |
| Token store | `MemoryTokenStore` by default; optional feature `secrets` -> `CredMgrTokenStore` (`MCP_TOKEN_CREDENTIAL_ID`) |
| Session approval | `SessionApprovalGate` Approve/Deny/Cancel channel (auto-deny by default; tests can auto-approve or drive the channel / `FakeMcpApprovalUi`) |
| Approval gate Fake glue | `FakeMcpToolApprovalGlue` (`approval.rs`) — thin gate **before** `execute_tool`: optional `FakeMcpSessionRegistry` → only registered **Connected** ids eligible; then Approve/Deny/Cancel; Deny/Cancel/channel-closed/dropped → fail closed; after Approve → live exec still unwired (`execute_tool` returns not-wired). `FakeMcpApprovalUi` scripts decisions (exhausted → Cancel). `Debug` = mode / counts only (**never** bearer tokens). **Not** wired into Streamable HTTP `dispatch_tool` yet |
| Surface | `GET /health` + MCP tools/list matching C# `McpSshTools` names: `list_sessions`, `run_command`, `send_text`, `read_terminal` (HTTP call stubs; **no** live tool execution) |
| Capability glue | `tools/list` shape (`ToolsListResponse`) -> secrets-free `McpCapabilityReport` for diagnostics / Settings Fake (`capability_report_from_tools_list` / `capability_report_for_bind`); `FakeMcpCapabilityServer` advertises catalog **without** socket bind or tool execution; off-loopback / port `0` / blank names / control-char names / duplicates fail-closed via bind helpers + summarizer; `execute_tool` always unwired; `Debug` / diagnostics text never carry bearer tokens |
| Session registry Fake | `FakeMcpSessionRegistry` / `McpSessionInfo` / `McpSessionStatus` (`session_registry.rs`) — register/unregister **already-open Connected** SSH session ids for the MCP tools catalog (C# `IMcpSessionRegistry` list surface; C# scans tabs, Lab Fake is explicit). Fail-closed: blank / control-char ids, non-Connected register, duplicate register, unknown unregister; `list_sessions` returns Connected only (insertion order); `get_connected` agent-readable unknown/not-connected errors; `Debug` = counts + ids only (**never** bearer tokens / passwords / terminal output). Consumed by approval-gate Fake glue when present; **not** wired into Streamable HTTP `dispatch_tool` yet |
| Shutdown order Fake glue | `FakeAppExitShutdownGlue` / `prepare_for_process_exit` (`shutdown_order.rs`) — records canonical exit steps: `FlushHttpWebViews` → `FlushBitwardenWebView` → `StopMcpServer` → `CloseAllSessions` (WebView/Bitwarden **before** MCP stop; wrong order → `ShutdownOrderError`). `prepare_for_process_exit` drives `HttpPlaceholderMcpHost` / any [`McpServerHost`] with 2s bounded stop (errors swallowed like C#). `Debug` = counts/flags only (**never** bearer tokens / URIs). **Not** wired into GPUI / WinUI `MainWindow` yet |
| Stateless | `NeverSessionManager` + `legacy_session_mode = false` (parity with C# `Stateless = true`) |
| `HttpPlaceholderMcpHost` | In-memory lifecycle only (no socket) -> available with `--no-default-features` |

```powershell
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features   # placeholder + token/approval/capability/session-registry helpers
```

Tests cover: real bind + health, reject bad/missing token, port `0` rejected, non-loopback / hostile bind strings rejected (unit + integration), tools list names, approval channel (Approve/Deny/Cancel + Fake UI), approval-gate Fake glue (Connected eligibility when registry present, deny/cancel fail-closed, execute_tool not wired, Debug redaction), capability glue (Fake report + off-loopback fail-closed + Debug redaction), session-registry Fake (Connected-only register, duplicate/unknown fail-closed, list order, Debug redaction), shutdown-order Fake glue (WebView/Bitwarden before MCP stop, wrong order fails, `prepare_for_process_exit` + placeholder host, Debug redaction).

---

## AppServices

```rust
wormhole_app::init_tracing();
let services = wormhole_app::services::build_default_services();
// services.tunnels, services.mcp, services.storage, services.secrets
```

```powershell
cargo check -p wormhole-app
```

---

## Non-goals (this milestone)

- Rewriting Go sidecars under `tools/`.
- Interactive OTP / SAML / Entra WebView2 **UI** (OTP prompt **trait + fakes + Channel UI glue** (`OtpPromptChannel` / `FakeOtpPromptUi` in `wormhole-ui` -> **no** GPUI dialog) and Entra token **trait + fakes** + refresh-token **cache path** stub exist; WatchGuard Firebox has **username/password + optional OTP typing + Fake** only -> HTTP/SAML not wired; Stormshield SNS has **username/password + `password+otp` typing + Fake + establish-path glue** only -> portal/cache/SSO not wired; Fortinet has **SAML path types + Fake / Channel callback + establish-path glue + `SamlPromptChannel` / `FakeSamlPromptUi` transport** -> **not** full WebView2 / external browser / live FortiGate; Cisco has **group / 2FA typing + prepare + establish-path glue** -> **no** STF/CSTP / live ASA and **no** SAML SSO / CSD / client cert; **interactive Entra WebView2 popup is not wired**; auth glue still constructs sidecar JSON from **resolved** materials only until portal / Azure loops call `request_otp` / `request_stormshield_otp` / `request_entra_access_token` / SAML callback).
- Wiring live SSH tabs / Fake registry / approval glue into Streamable HTTP `McpSshTools` dispatch (tool **names** + `FakeMcpSessionRegistry` list/register + `FakeMcpToolApprovalGlue` Approve/Deny/Cancel before `execute_tool` exist; HTTP `list_sessions` still returns `[]` and `run_command` / `send_text` / `read_terminal` stay unwired — capability + approval-glue `execute_tool` fail-closed).
- Changing any C# production code.

---

## Tunnel secret payloads (DPAPI store)

Provider secrets are **not** columns on SQLite `TunnelConfigs`. C# / Rust keep
metadata in the DB and the opaque blob under
`%LOCALAPPDATA%\Wormhole\tunnels\<tunnelConfigId:N>.dpapi` (null entropy).

Rust (`wormhole-secrets-win`, distinct from private-key `KeyMaterialStore`):

| API | Role |
|---|---|
| `TunnelPayloadStore` | DI store / read / delete |
| `DpapiTunnelPayloadStore` | Confined DPAPI under `tunnels\` (or injectable root) |
| `FakeTunnelPayloadStore` | In-memory tests; `Debug` = lengths / call counts only |
| `write_tunnel_payload(_under)` / `read_*` / `delete_*` | Free helpers; path confinement **before** I/O; missing delete ? `Ok(())`; **never** unprotect on delete |

Hostile roots (`..`, empty, absolute escape, join-replacement) ? `PathNotConfined`
with **no** path/secret in Display/Debug. Sibling `keys\` is never touched (same
guid under both roots stays isolated). See [04-secrets.md](04-secrets.md) and
[adversarial-ledger-tunnel-payload-dpapi.md](adversarial-ledger-tunnel-payload-dpapi.md).
Not wired into live `TunnelManager::establish` here ? load the blob, then pass
resolved materials / stdin JSON to providers.


