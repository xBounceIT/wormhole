# Update check + logging parity (`wormhole-update` / `wormhole-app`)



**Status:** Version compare + SHA verify + tracing daily file green · check channel stubbed (Fake + fail-closed network) · Settings/UI notify glue stubbed (`check_now` → Available/None/Error) · logging boot/settings glue (`apply_logging_boot` + `FakeLogSink`) · live HTTP / installer UX stubbed



**Date:** 2026-07-31



**C# mirrors:** `Services/UpdateService.cs`, `Services/IUpdateService.cs`, `Models/UpdateCheckResult.cs`, `ViewModels/UpdateViewModel.cs`, `Helpers/LogFiles.cs`, `App.xaml.cs` Serilog setup



**Adversarial ledgers:** [`adversarial-ledger-update-logging.md`](adversarial-ledger-update-logging.md) (version/download/logging) · [`adversarial-ledger-update-channel.md`](adversarial-ledger-update-channel.md) (`UpdateChecker` / Fake / `UpdateApiToken`) · [`adversarial-ledger-log-redaction.md`](adversarial-ledger-log-redaction.md) (`redact_log_text` assignment scrubbing) · [`adversarial-ledger-logging-boot.md`](adversarial-ledger-logging-boot.md) (`apply_logging_boot` / `FakeLogSink`)



---



## Logging (`wormhole-app`)



| Item | Parity |

|---|---|

| Directory | `%LOCALAPPDATA%\Wormhole\logs\` (AGENTS.md) — created on `init_tracing` |

| Daily file name | `wormhole-yyyyMMdd.log` (Serilog / `LogFiles.GetLogFilePath`) |

| Sinks | Daily append file + stderr |

| Filter | `RUST_LOG` or default `info` |

| Redaction | Writer hook → `redact_log_text` → Bitwarden CLI patterns (via `wormhole_secrets_win` when feature `secrets` is on) **plus** case-insensitive `password=` / `token=` / `secret=` / `SVPNCOOKIE=` / `BW_SESSION=` assignments (optional spaces around `=`; non-empty `\S+` values). Bare `key=` left intact. **Not** full free-form secret scrubbing. |

| Boot / settings glue | `logging_boot` — `LoggingBootConfig` / `apply_logging_boot` / `enrich_log_line` wire settings-shaped retention + redaction enable into the existing enricher (no reimplementation). `AppliedLogging` is normalized-only (private fields). Binary calls `apply_logging_boot(LoggingBootConfig::production_default())` before `init_tracing`. Production file/stderr always redact via the writer hook; `redaction_enabled` gates `enrich_log_line` / `FakeLogSink` only. Lab: `FakeLogSink` (no GPUI / no file sink). |



```powershell

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

cd rust

cargo run -p wormhole-app --bin wormhole-app

```



Retention deletion (C# `retainedFileCountLimit` / settings) is **not** implemented in Rust yet — `DEFAULT_LOG_RETENTION_DAYS = 14` is documented for a future host job. `normalize_retention_days` mirrors C# `LogFiles.NormalizeRetentionDays` (1..=365, else default) so settings apply can clamp before a host deletion job lands.



### Boot glue (`logging_boot`)



| Type / fn | Role |

|---|---|

| `LoggingBootConfig` | Settings snapshot: `redaction_enabled` (production default `true`) + raw `retention_days` |

| `apply_logging_boot` | Normalize retention (1..=365 else default); record redaction enable (does **not** replace `init_tracing`) |

| `AppliedLogging` | Normalized snapshot; construct only via apply (accessors; fields private) |

| `enrich_log_line` | When enabled → `redact_log_text`; else passthrough |

| `FakeLogSink` | Records enriched lines for unit tests / Lab (no GPUI); `apply_config` does not clear prior lines |



### Non-goals (logging)



- Serilog enrichers / MEL bridge

- MCP Kestrel → Serilog routing

- Automatic deletion of aged `wormhole-*.log` files

- Full secret scrubbing of free-form log text (prose / JSON `:"…"` / unlabeled values). Only Bitwarden CLI patterns and the listed `key=` assignments are stripped.

- GPUI / settings chrome for logging (Fake + apply only)

- Reimplementing `redact_log_text` inside the boot glue



---



## Update crate (`wormhole-update`)



Workspace member mirroring the **pure** pieces of `UpdateService`:



| Module | Role |

|---|---|

| `version` | `TryParseTagVersion` + `System.Version`-style compare (`i32` component ceiling) |

| `github` | Repo URL parse (GitHub http(s) only), installer asset match, SHA sidecar parse, `is_allowed_http_url` scheme floor |

| `check` | `UpdateCheckResult` + `evaluate_release` (no HTTP; rejects `file://` installer URLs + unsafe file names) |

| `channel` | `UpdateChecker` trait + `NetworkStubUpdateChecker` (fail-closed) + `FakeUpdateChecker` + redacted `UpdateApiToken` |

| `notify` | `check_now` + `UpdateNotifyStatus` (`Available` / `None` / `Error`) — thin map over the channel; no HTTP |

| `changelog` | `ChangelogDocument::from_manifest` (drops non-http(s) release URLs) + live fetch stub |

| `download` | `download_bytes_to_temp` / `_limited` + SHA-256 verify-before-write; `MAX_INSTALLER_BYTES` (512 MiB) fail-closed |



Cache directory helper: `%LOCALAPPDATA%\Wormhole\cache\updates` (`AppPaths.GetUpdateCacheDirectory`).



### Check channel (`UpdateChecker`)



Injectable surface mirroring `IUpdateService.CheckAsync` without sockets:



| Type | Behavior |

|---|---|

| `NetworkStubUpdateChecker` | Production stub — **no HTTP**, ignores API tokens, returns `UpdateCheckResult::failed` (`check_failed = true`) |

| `FakeUpdateChecker` | Tests — scripted `UpdateCheckResult` / `ReleaseManifest` evaluation; empty queue fail-closed; records token **presence/len only** (`None` / empty `Some("")` → absent) |

| `check_for_update_network_stub` / `check_for_update_live_stub` | Free helpers → `UpdateError::CheckNetworkStub` |

| `UpdateApiToken` | Opaque PAT/bearer — `Debug`/`Display` redact; **never** log `expose()` |



`UPDATE_CHECK_NETWORK_GAP` documents the missing live client for hosts/UI copy.



### Notify glue (`check_now` → Available / None / Error)



| Layer | Role |
|---|---|
| `wormhole-update::notify` | `check_now(checker, request)` → `UpdateNotifyStatus` (`Available` / `None` / `Error`); pure map of `UpdateCheckResult` / channel `Err` |
| `wormhole-ui` feature `update` | `UpdateNotifyGlue` — Settings bindings (`status_text`, info bar, `LastUpdateCheck` stamp on success, skipped-version dismiss, startup `AutoCheckForUpdates`); Fake / NetworkStub only |



Fail-closed notify map: empty/exhausted Fake, `NetworkStubUpdateChecker`, and channel `Err` → `UpdateNotifyStatus::Error` (never advertises). UI glue preserves a previously surfaced update on Error (C# `ApplyResult` parity), and `dismiss` records `SkippedUpdateVersion` from the remembered advertised version (C# `LatestKnown`) even when the status line was overwritten by a transport error. API tokens stay inside `UpdateCheckRequest` and never appear in glue `Debug`.



### Fail-closed contracts (adversarial)



- Path traversal / multi-component installer names → `UnsafeFileName` (no write)

- Hash mismatch → no `.part` / final written

- Payload `len > max` → `InstallerTooLarge` before write

- Manifest installer URL schemes other than `http`/`https` → treat as no update

- Attacker-controlled error context strings clipped to 256 chars

- Network stub / empty or exhausted fake queue → never advertises an update; never opens sockets

- Fake `seen_requests` retains token presence/len only (`None`/empty → absent); never the value

- API tokens never appear in `Debug` of requests / fakes / gap strings / notify glue

- `check_now` / notify: exhausted Fake + hostile `is_update_available` without `latest_version` → Error (never advertise)
- UI glue: Error preserves prior info-bar availability; `dismiss` after Error still persists skip via remembered version
- UI glue: successful Available/None stamps `LastUpdateCheck`; Error does not; startup respects `AutoCheckForUpdates` / development builds



### Wired in app



Feature `update` (default) links `wormhole-update` into `wormhole-app`. The bootstrap binary logs arch + a placeholder current version; it does **not** call GitHub. Hosts should inject `NetworkStubUpdateChecker` (or a future HTTP checker) via `UpdateChecker`, and bind Settings Updates through `wormhole-ui::UpdateNotifyGlue` (`check_now`).



### Non-goals (update — explicit)



- Live `HttpClient` / GitHub `releases/latest`

- Installer UX (download progress, changelog WebView2, silent launch)

- Silent launch (`/SILENT /RESTARTAPP`) + `Environment.Exit`

- Mark-of-the-Web strip (`:Zone.Identifier`)

- Cache rotation of prior `Wormhole-*-setup.exe` files

- Full Settings throttle UX (persist cadence UI); glue may stamp `LastUpdateCheck` on successful Fake/stub answers only

- Host allow-list beyond http(s) scheme floor (C# download client likewise has no host allow-list)



Hosts should supply release JSON / bytes (tests or future HTTP layer) and call `evaluate_release` / `download_bytes_to_temp`, or inject `FakeUpdateChecker` / a future HTTP `UpdateChecker`, then `check_now` / `UpdateNotifyGlue`.



### Pins



| Crate | Pin |

|---|---|

| `sha2` | `=0.11.0` |

| `hex` | `=0.4.3` |



Context7 MCP was unavailable; versions from `cargo info` / crates.io (2026-07-31).



---



## Verification



```powershell

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

cd rust

cargo test -p wormhole-update

cargo test -p wormhole-ui

cargo test -p wormhole-app

cargo run -p wormhole-app --bin wormhole-app

```

