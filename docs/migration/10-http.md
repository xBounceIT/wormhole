# HTTP/HTTPS target types — `wormhole-http`

**Status:** pure Rust port of `HttpConnectionTarget` + browser-arg helper + Bitwarden profile fingerprinting + Fake-WebView nav-result glue + non-extension WebView2 profile isolation / wipe Fake glue + new-window / popup policy Fake glue
**Date:** 2026-07-31

## Scope

C# source of truth: `ViewModels/Sessions/HttpSessionViewModel.cs` (`HttpConnectionTarget`, `BuildTargetAsync`, `ReportNavigationSucceeded` / `ReportNavigationFailed`), `Views/Sessions/WebBrowserView.xaml.cs` (`OnNavigationCompleted`, `OnNewWindowRequested`, shared vs isolated env selection, `BuildBitwardenPopupUri`), `Helpers/WebViewNewWindowNavigation.cs`, `Helpers/WebViewBrowserArguments.cs`, `Helpers/AppPaths.cs` (`GetWebBrowser*`), `App.xaml.cs` (`ClearWebBrowserUserData`), and `Services/BitwardenBrowser/BitwardenBrowserWebViewProfile.cs` (path/arg helpers only).

This crate owns **navigation description**, **Bitwarden profile folder fingerprinting**, a **Fake WebView navigation-result → session-status glue** stub (`nav_report`), **non-extension WebView2 profile isolation / wipe Fake glue** (`profile_wipe`), and **new-window / popup policy Fake glue** (`new_window`). WebView2 HWND hosting stays in `wormhole-surface-win` (wired later). Absolute Bitwarden roots (`bitwarden-browser-webview2\…`) live in `wormhole-secrets-win` path helpers.

| Type / fn | C# analogue |
|---|---|
| `HttpConnectionTarget` | `HttpConnectionTarget` record |
| `HttpCertPolicy::{Default,IgnoreErrors}` | resolved `IgnoreCertErrors` after scheme gate |
| `cert_policy_to_webview2_behavior` (surface-win) | `Default`→validate / `IgnoreErrors`→`AlwaysAllow` mapping only; COM not subscribed |
| `http_ignore_cert_to_webview2_behavior` / `target_cert_to_webview2_behavior` | leaf `HttpIgnoreCertErrors` / built target → same adapter (fail-closed) |
| `Socks5Proxy` | `IPEndPoint? Socks5Proxy` |
| `build_direct_target` | tunnel == null branch |
| `build_socks_target` | tunnel with `Socks5Endpoint` |
| `build_forwarder_target` | `BindLocalForwarderAsync` + loopback URI |
| `select_http_tunnel_route` / `HttpTunnelRoute` | prefer SOCKS else forwarder (pure; Serial N/A) |
| `FakeHttpTunnelRoute` | offline tunnel view for route-selection unit tests |
| `effective_ignore_cert` / `resolve_cert_policy` | HTTPS ∧ `HttpIgnoreCertErrors` → bool / enum |
| `HttpConnectionTarget::ignore_cert_errors` | `IgnoreCertErrors` bool accessor |
| `validate_host` / `build_navigate_uri` | Reject empty / injection-prone hosts; bracket IPv6 |
| `build_browser_arguments` | `WebViewBrowserArguments.Build` |
| `is_https_target` / `ensure_https_bitwarden_target` | `BitwardenBrowserWebViewProfile.IsHttpsTarget` (+ fail-closed gate) |
| `build_bitwarden_browser_arguments` | `BuildBrowserArguments` |
| `build_context_folder_name` | `BuildContextFolderName` |
| `build_persistent_route_key` | `BuildPersistentRouteKey` (HTTPS-only; `None` for http) |
| `user_data_folder` / `user_data_folder_for_target` | `GetUserDataFolder` overloads (root injected; target overload returns `Result`, rejects non-HTTPS) |
| `HttpNavSession` / `FakeWebViewSurface` / `NavigationOutcome` | VM report path + view `NavigationCompleted` (Fake only; no GPUI / WebView2) |
| `apply_navigation_report` / `validate_navigate_uri` | success→Connected / fail→Failed / cancel no-op; empty URI fail-closed |
| `keyed_shared_folder_name` / `keyed_shared_folder_fingerprint_args` | `WebViewBrowserArguments.KeyedSharedFolderName` (SHA-256 of hardening → `shared-` + 8 hex) |
| `requires_isolated_web_profile` / `select_web_browser_profile_kind` | SOCKS **or** ignore-cert → isolated `env-<id>`; else shared |
| `web_browser_shared_user_data` / `web_browser_isolated_user_data` | `GetWebBrowserShared*` / `GetWebBrowserIsolated*` (root injected) |
| `select_web_browser_user_data_folder` (+ `_for_target`) | Resolve concrete UDF under `webview2-web\` |
| `stale_keyed_folder_names` / Fake `sweep_stale_keyed_folders` | `SweepStaleKeyedFolders` selection (keep current fingerprint; leave `env-*`) |
| `FakeWebBrowserProfileStore` / `clear_web_browser_user_data` | `App.ClearWebBrowserUserData` — Fake wipe of non-extension web root only |
| `NewWindowPolicy::{AllowInTab,HostPopup,Block}` | `OnNewWindowRequested` + Bitwarden in-app popup decision |
| `get_in_session_navigation_uri` / `decide_new_window_policy` | `WebViewNewWindowNavigation.GetInSessionNavigationUri` (+ AllowInTab/Block) |
| `build_bitwarden_popup_uri` / `decide_bitwarden_popup` | `BuildBitwardenPopupUri` → HostPopup (never unmanaged Edge) |
| `FakeNewWindowSurface` | Unit-test recorder for new-window / Bitwarden popup decisions |

### Navigation result glue (`nav_report`)

Mirrors the C# split where the VM owns lifecycle status and the view reports the
initial top-level navigation:

| Outcome | Status (only while `Connecting`) |
|---|---|
| `Succeeded` | `Connected` (clears error) |
| `Failed { message, transport_failure }` | `Failed` (+ message); probe not stubbed |
| `Cancelled` | **no change** (C# `OperationCanceled` keeps waiting) |

Late reports after Connected / Failed / Disconnected are ignored (including late
`Cancelled`). `Cancelled` while Connecting keeps waiting so a later success/fail
still applies. Empty or whitespace-only `navigate_uri` fails closed
(`HttpError::EmptyNavigateUri`) at `HttpNavSession::begin` and
`FakeWebViewSurface::navigate` before the Fake surface records a navigation
(session target is immutable after begin). Resolved `HttpCertPolicy` on the
target is **preserved** through begin / Fake navigate / success / fail / cancel
(ignore-cert already gated by builders). No secret logging: `Debug` for outcomes
/ sessions prints lengths and URI/policy only.

**Non-goals for this stub:** live WebView2, GPUI, SOCKS reachability probe after
transport failure, AlwaysAllow COM subscribe (surface-win mapping only).

### Profile isolation / wipe Fake glue (`profile_wipe`)

Mirrors C# regular-web (non-Bitwarden) environment identity and startup cleanup:

| Rule | Behavior |
|---|---|
| Fingerprint | `keyed_shared_folder_name` = `shared-` + first 8 hex of SHA-256(hardening args) — golden `shared-815e5671` |
| Shared tab | No SOCKS and no ignore-cert → `web_root/shared-<fingerprint>` |
| Isolated tab | SOCKS **or** resolved `IgnoreErrors` → `web_root/env-<id>` (id required) |
| Startup wipe | `FakeWebBrowserProfileStore::clear_web_browser_user_data` clears **all** web folders; Bitwarden root untouched |
| Stale keyed sweep | Removes other `shared-*` siblings; keeps current fingerprint + `env-*` / foreign names; empty / non-`shared-*` keep → no-op |
| Fail-closed | Empty / whitespace web or Bitwarden roots; empty / hostile isolated ids; web≡Bitwarden root collision |
| Secrets | `Debug` prints lengths / counts only — never full paths or isolated ids |

Production still wipes `%LOCALAPPDATA%\Wormhole\webview2-web\` at launch
(`App.ClearWebBrowserUserData`). This Fake store is in-memory only (no disk I/O).
`wormhole-surface-win` lab `unique_user_data_dir` remains a separate temp-folder
helper for child HWND hosts — not a substitute for this shared/isolated contract.

### New-window / popup policy Fake glue (`new_window`)

Mirrors C# `WebViewNewWindowNavigation` + `WebBrowserView.OnNewWindowRequested`
and documents the Bitwarden in-app popup path (`BuildBitwardenPopupUri`):

| Decision | When |
|---|---|
| `AllowInTab` | Same-origin / remappable new-window URI → navigate existing tab (`Handled=true`) |
| `HostPopup` | Bitwarden `chrome-extension://{id}/{popup}` only — hosted in-app WebView2 |
| `Block` | Empty / whitespace / `about:blank` / unroutable cross-origin / userinfo / bad Bitwarden inputs |

**Rules (parity + fail-closed):**

1. Session `NewWindowRequested` **never** opens an unmanaged Edge window (would
   bypass per-tab SOCKS / cert / tunnel). Outcome is AllowInTab or Block only —
   HostPopup is **not** returned from `decide_new_window_policy`.
2. Forwarder tabs: same origin as routed navigate URI → AllowInTab as-is; same
   origin as `original_uri` → rewrite scheme/host/port to the loopback forwarder
   (path/query/fragment preserved); else Block.
3. Bitwarden toolbar / activation uses `decide_bitwarden_popup` /
   `build_bitwarden_popup_uri` → HostPopup (or Block on empty / hostile id/path).
   Never main-tab AllowInTab for that path.
4. Empty / whitespace raw URI, `about:blank` (+ `?`/`#`), embedded userinfo, and
   relative/unparsable targets (when both bases present) **fail closed** → Block.
5. Secrets: `Debug` prints lengths / scheme / policy kind only — never full URIs,
   extension ids, or query strings.

**Non-goals for this stub:** live WebView2 `NewWindowRequested` wiring, GPUI popup
dialogs, Bitwarden extension install / storage bridge, changelog external-link
open (separate `UpdateChangelogView` path).

## Routing rules (parity)

1. **Direct** — `scheme://host:port/`, no proxy, `original_uri = None`
2. **SOCKS** — same real URI; `socks5_proxy` set; WebView2 gets `--proxy-server=socks5://…`
3. **Forwarder** — navigate `http(s)://127.0.0.1:<local>/`; `original_uri` keeps appliance origin; cert name won't match → HTTPS needs ignore-cert

### Tunnel target selection (`select_http_tunnel_route`)

Pure preference over an optional tunnel lease view (no bind I/O) — same hybrid as C#
`BuildTargetAsync` / session `connect_http`:

| Lease | `Socks5Endpoint` | Route |
|---|---|---|
| absent | — | `Direct` → `build_direct_target` |
| present | present (port ≠ 0) | **prefer** `Socks5` → `build_socks_target` |
| present | absent | `LocalForwarder` → caller `BindLocalForwarder` then `build_forwarder_target` |

Port-`0` SOCKS is rejected (`InvalidPort`). Unlike SFTP/SSH (fail closed without SOCKS),
HTTP always falls back to the loopback forwarder when the lease has no SOCKS.

**Serial never applies** — Serial is local COM and skips VPN entirely in the
orchestrator; this selector is HTTP/HTTPS-only (`HttpScheme::{Http,Https}`).
RDP/VNC always use the forwarder path outside this crate.

Cert policy is resolved only by the builders (`resolve_cert_policy` / HTTPS ∧ leaf
flag) and is preserved across Direct / SOCKS / forwarder construction.

### Cert policy (`HttpCertPolicy`)

Leaf storage is still `HttpIgnoreCertErrors` (bool on the profile). It is **leaf-only**
(not folder-inherited — unset leaf resolves to `false`). Builders gate like C#
`BuildTargetAsync`: `cert_policy = IgnoreErrors` only when scheme is HTTPS **and** the leaf
flag is true; plain HTTP always resolves to `Default` even if the leaf flag is set.
Public leaf → policy resolution is `resolve_cert_policy` / `effective_ignore_cert` only
(HTTPS ∧ leaf flag). Scheme is typed `HttpScheme` (URI builders emit lowercase
`http`/`https` only — no case-variant string path into policy).

**WebView2 AlwaysAllow glue (surface-win, not this crate):**
`wormhole-surface-win` (`webview` feature) exposes
`cert_policy_to_webview2_behavior(HttpCertPolicy) → WebView2CertErrorAction::{Default,AlwaysAllow}`
plus thin leaf/target helpers
`http_ignore_cert_to_webview2_behavior(scheme, HttpIgnoreCertErrors)` /
`target_cert_to_webview2_behavior(&HttpConnectionTarget)` that chain through
`resolve_cert_policy` — **fail-closed** unless HTTPS ∧ leaf true
(`Default` stays validate; `IgnoreErrors` alone maps to `AlwaysAllow`).
Leaf glue consumes the **profile-resolved** leaf bool (never OR folder inherit).
Target glue preserves the same matrix across direct / SOCKS / forwarder builders.
They do **not** subscribe `ServerCertificateErrorDetected`. Surface-lab gates 3–5 /
`ChildWebViewHost::create` leave default cert validation
(**lab ≠ production:** AlwaysAllow is **not** applied in lab/create until the
production HTTP host wires the COM handler on an isolated user-data folder).
Do not treat Chromium `--ignore-certificate-errors` as a create-time shortcut.
C# reference: `WebBrowserView.OnServerCertificateErrorDetected` → `AlwaysAllow`.
Ledger: [adversarial-ledger-http-cert-glue.md](adversarial-ledger-http-cert-glue.md).

HTTP(S) targets are credential-less — never log passwords, private keys, or tunnel secrets
with target/Debug output. Browser args carry hardening + optional SOCKS endpoint only.
`HttpConnectionTarget` / `HttpCertPolicy` `Debug` prints URI, proxy, policy, and route only.

Ports must be in `1..=65535` (including SOCKS / local forwarder ports). Hosts reject path/`@`/embedded-port/`scheme:` injection; surrounding whitespace is trimmed.

## Bitwarden profile helpers

HTTPS-only: `user_data_folder_for_target` / `ensure_https_bitwarden_target` reject plain HTTP and non-`https` logical origins (use `original_uri` for loopback forwarders). Absolute profile roots in `wormhole-secrets-win` reject path-traversal segments.

```rust
use wormhole_http::{
    build_bitwarden_browser_arguments, build_context_folder_name,
    build_persistent_route_key, user_data_folder_for_target,
};
use wormhole_secrets_win::bitwarden_browser_webview2_root;

let args = build_bitwarden_browser_arguments(None);
let folder = build_context_folder_name(&args, false); // "profile-" + 16 hex
let path = user_data_folder_for_target(
    &bitwarden_browser_webview2_root(),
    &args,
    false,
    "https://router.example/login",
    None,
    Some(tunnel_id),
)?;
```

Route key material matches C#: `{guid:N}\0{socks5|forwarder}\0{authority-lowercase}` → SHA-256 hex.
Context folder: SHA-256(`args + "\0cert=" + 0|1`) → `profile-` + first 16 hex chars.
Browser args are hardening + optional `socks5://host:port` only — no session tokens.

## Non-goals

- Creating WebView2 environments / GPUI browser panes
- Bitwarden extension **download** / install / cookie-IndexedDB seeding
- Live disk wipe of `%LOCALAPPDATA%` (Fake store only; C# `App` still owns startup wipe)
- Tunnel establishment (callers use `wormhole-tunnels`)
- Live nav-result / new-window wiring into `wormhole-session` `SessionHandle` (Fake glue is crate-local)
- Live `CoreWebView2.NewWindowRequested` subscription / HWND popup hosting

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
cargo test -p wormhole-session --test orchestrator_fakes
cargo test -p wormhole-surface-win --features webview --lib
```

`wormhole-http` covers builders + `select_http_tunnel_route` (SOCKS prefer / forwarder /
Direct / port-0 / cert composition / Serial N/A) + `nav_report` (success / fail /
cancel / empty-URI fail-closed / cert-policy preserve / no-secret Debug) +
`profile_wipe` (keyed fingerprint, shared vs isolated, Fake wipe leaves Bitwarden,
stale keyed sweep, empty-path fail-closed, Debug redaction) + `new_window`
(AllowInTab / HostPopup / Block, forwarder rewrite, about:blank + empty fail-closed,
Bitwarden popup URI, userinfo Block, Debug redaction).
`orchestrator_fakes` covers `connect_http` wiring (Direct without lease, SOCKS prefer,
forwarder fallback, port-0 reject, Serial skips tunnel). The surface-win command covers
`cert_policy_to_webview2_behavior` / leaf+target AlwaysAllow glue mapping tests
(no COM / Runtime required).