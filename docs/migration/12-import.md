# mRemoteNG import + backup envelope (`wormhole-import`)

**Status:** XML parse + **SSH / RDP / VNC only** plan green · password AES-GCM (16-byte nonce) green · backup envelope inspect green · **plan → SQLite apply stub** green (`ConnectionRepository::insert_many`) · **soft-skip → user-facing skip report** green (`ImportSkipReport` / Fake; no GPUI)

**Date:** 2026-07-31

**C# mirrors:** `Services/MRemoteNg/*`, `Models/MRemoteNg*.cs`, `Models/Backup/*`

---

## Supported protocols (import)

| mRemoteNG `Protocol` | Wormhole mapping |
|---|---|
| `SSH` / `SSH1` / `SSH2` | `ProtocolType::Ssh` |
| `RDP` | `ProtocolType::Rdp` |
| `VNC` | `ProtocolType::Vnc` |

Everything else is **not imported** as a connection leaf. Classification:

[`ImportError::UnsupportedProtocol`](../../rust/crates/wormhole-import/src/error.rs) via

[`try_map_protocol`](../../rust/crates/wormhole-import/src/protocol.rs). Planning **soft-skips**

those leaves (`ImportPlan.skipped` + `skipped_samples`); the whole import does not fail.

Soft-skipped leaves never reach SQLite — [`apply_import_plan`](../../rust/crates/wormhole-import/src/apply.rs) only inserts `plan.nodes`.

### Soft-skip → user-facing report (glue stub)

Thin secrets-free glue in [`skip_report`](../../rust/crates/wormhole-import/src/skip_report.rs) — **report surface only** (does not re-apply / write SQLite):

| Concern | Behavior |
|---|---|
| Input | `ImportPlan.skipped` + `skipped_samples` (`name: protocol` samples, ≤ 5) |
| Output | [`ImportSkipReport`](../../rust/crates/wormhole-import/src/skip_report.rs) with structured entries (`name`, `protocol`, `reason`) |
| Sample parse | Trailing protocol via `rsplit_once(": ")` so names that contain `: ` stay intact |
| Empty skips | Valid — empty report + empty `format_skip_summary` |
| Summary | `format_skip_summary` → InfoBar-style text (count + sample lines; full reason, never truncated; `+N more` only when samples were listed and capped) |
| Passwords | Never read `PlannedNode.password_plaintext`; report / `Debug` / Fake have no credential fields |
| Fake | [`FakeImportSkipReporter`](../../rust/crates/wormhole-import/src/skip_report.rs) — canned or plan-driven; Fake `Debug` is counts-only; **no GPUI** |

### Protocol gaps (explicit non-goals for this spike)

| Gap | Notes |
|---|---|
| **HTTP** | Wormhole has `ProtocolType::Http`; mRemoteNG `HTTP` Connection leaves are skipped |
| **HTTPS** | Wormhole has `ProtocolType::Https`; fixture `appliance-https` is skipped |
| **Serial** | Wormhole has `ProtocolType::Serial`; fixture `console-serial` is skipped |
| Telnet / RAW / ICA / … | Unmapped; soft-skipped on Connection leaves like HTTP/HTTPS/Serial (`try_map_protocol` → `UnsupportedProtocol`; `plan_nodes` continues) |
| Field mapping for HTTP/Serial | No host/port/baud/cert-policy import mapping yet — do not invent |

Matches AGENTS.md: *“mRemoteNG import remains SSH/RDP/VNC-only (no HTTP/HTTPS/Serial yet).”*

Containers whose `Protocol` attribute is unmapped still become folders with `protocol = None`.

---

## Crate

| Module | Role |
|---|---|
| `mremoteng` | Parse `<mrng:Connections>` → raw node tree; `plan_nodes` for folders + SSH/RDP/VNC |
| `protocol` | `map_protocol` / `try_map_protocol` — SSH/RDP/VNC only; gaps → `UnsupportedProtocol` |
| `crypto` | Password / `Protected` decrypt — AES-256-GCM **16-byte nonce** (BouncyCastle parity) |
| `backup` | `BackupDocument` envelope + `inspect_backup_json` (no PBKDF2/AES yet) |
| `apply` | **Write stub:** `planned_to_connection_node` + `apply_import_plan` → `ConnectionRepository::insert_many` (feature `storage`) |
| `skip_report` | **Report stub:** `ImportPlan` soft-skips → `ImportSkipReport` / `format_skip_summary` + `FakeImportSkipReporter` (no GPUI) |

Workspace member: `rust/crates/wormhole-import`. Fixture: `wormhole-testkit/fixtures/mremoteng-sample.xml`.

Features: `domain` (default) + `storage` (default; pulls `wormhole-storage`).

### Plan → SQLite apply stub

Mirrors the node-insert half of C# `MRemoteNgImportService.CommitAsync` (without Credential Manager):

| Concern | Behavior |
|---|---|
| Input | `ImportPlan.nodes` (DFS parent-before-child from `plan_nodes`) |
| Mapping | `planned_to_connection_node` → `wormhole_domain::ConnectionNode` |
| Batch | **One transaction** via `ConnectionRepository::insert_many` — not per-row commit; FK failure rolls the whole batch back |
| Soft-skips | Already excluded from `plan.nodes`; counted only in `ApplyImportResult.skipped`. Apply also **fail-closes** if a hand-crafted plan still carries HTTP/HTTPS/Serial (`InvalidData`) — nothing is written |
| Passwords | `password_plaintext` is **ignored** on apply (no `CredentialProfiles` / CredMgr yet); `credential_id` / `use_inline_password` stay unset |
| RDP domain | Copied to `rdp_domain` when protocol is `Rdp` or unset (folder); never for SSH/VNC |
| Empty plan | No-op success (`inserted = 0`) |
| Atomicity | `insert_many` is one transaction: FK failure, duplicate PK, or child-before-parent rolls the whole batch back |

Hostile XML (DOCTYPE / `..` / size / nesting) still fail-closed at parse time — apply never sees them.

### Password decrypt (ConfVersion 2.7)

Layout matches `MRemoteNgCrypto.cs` / mRemoteNG `AeadCryptographyProvider`:

| Field | Bytes |
|---|---|
| salt | 16 |
| nonce | **16** (not 12) |
| ciphertext | variable |
| tag | 16 |

- KDF: PBKDF2-HMAC-SHA1 → 32-byte key (`KdfIterations` from root)
- AAD = salt
- Rust uses `aes_gcm::AesGcm<Aes256, U16>` — same reason C# uses BouncyCastle instead of `System.Security.Cryptography.AesGcm`
- Empty `Password` → no credential
- Bad ciphertext / wrong password / invalid UTF-8 → [`DecryptError`]; **never** forged plaintext
- Derived PBKDF2 key uses `zeroize::Zeroizing` (wipe on drop / panic — C# `ZeroMemory` parity)
- Fixture `cipher-ssh` uses a **known test vector** (plaintext `lab-secret`, import password `import-pw`); `bad-cipher-ssh` stays fail-closed (`AAAAAA==`)
- Regressions cover tampered AAD (salt), flipped tag/ciphertext, truncated tag, and error Display/Debug never echoing the import password

Pins: `aes-gcm =0.11.0`, `pbkdf2 =0.12.2`, `sha1 =0.10.6`, `zeroize =1.9.0` (see workspace `Cargo.toml` / [deps-pins.md](deps-pins.md)).

### Backup envelope (optional spike)

`BackupDocument` / `BackupInspectResult` cover schema version + `encryption` (`none` | `aes-gcm`) without pulling Credential Manager / DPAPI secrets. `inspect_backup_json` / `inspect_backup_path` use a **slim envelope** (no payload materialization), reject unsupported encryption, cap files at 64 MiB (`MAX_IMPORT_FILE_BYTES`), and reject `..` / NUL path components.

### XML safety

- `DOCTYPE` / DTD → rejected (XXE / billion-laughs surface)
- Nesting depth ≤ 4096; node count ≤ 100_000
- Path reads go through `read_file_capped`
- `PlannedNode` / raw password fields redact in `Debug`

---

## Non-goals (this spike)

- Credential Manager / `CredentialProfiles` secret writes (node apply stub only)
- Full-file encryption exports
- Bitwarden / live secret material in fixtures
- Changing any C# production code
- **HTTP / HTTPS / Serial import mapping** (see gap table above)
- RDP resolution / screen-size import mapping on apply
- GPUI / WinUI import dialog wiring for skip summaries (Fake reporter only)

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import
cargo test -p wormhole-storage
cargo test -p wormhole-testkit
```
