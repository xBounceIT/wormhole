# Adversarial ledger — SSH known_hosts

**Scope:** `rust/crates/wormhole-ssh` (`known_hosts.rs`, `accept_server_host_key`, `SshConnectOptions` host-key wiring), `docs/migration/06-ssh-spike.md`  
**Date:** 2026-07-31  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (post-fix; adversarial renewed after simplify)

## Baseline

- `cargo test -p wormhole-ssh` and `--no-default-features` green before known_hosts hardening.
- Compared against `Services/Ssh/SshHostKeyValidator.cs` and `Wormhole.Tests/Services/SshHostKeyValidatorTests.cs` (fingerprint vector UTF-8 `"test"`).
- Context7 MCP unavailable; C# sources used as fingerprint/TOFU authority.

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| KH-A1 | P1 | `known_hosts::load` | Corrupt / hostile lines hard-failed the entire load | **Fixed** — soft-skip invalid lines; invalid UTF-8 → empty store |
| KH-A2 | P1 | `accept` / `pin` | No format checks; newline/space fingerprints could poison the file | **Fixed** — `validate_host_token` + `validate_fingerprint` (`SHA256:` + unpadded Base64) |
| KH-A3 | P1 | `save` | Fixed `known_hosts.tmp` + plain `rename` (not Windows replace-safe / concurrent-safe) | **Fixed** — unique `path.{pid}.{nanos}.{seq}.tmp` + `MoveFileEx(REPLACE)` |
| KH-A4 | P1 | `accept` TOFU | `pin` then failed `save` left an in-memory pin → later Trust without disk | **Fixed** — rollback `entries.remove` on save error + regression |
| KH-A5 | P2 | mismatch path | No explicit disk/memory pin-unchanged regressions | **Fixed** — `mismatch_never_overwrites_disk` + TOFU assertions |
| KH-A6 | P2 | docs | Risk of reading spike as production SSH UI / profile-pin parity | **Fixed** — `06-ssh-spike.md` spike wording + non-goal for cross-process merge |
| KH-R1 | — | `decide("")` | C# throws `ArgumentException`; Rust returns `Mismatch` | **Rejected** — intentional soft-fail; `accept` still errors on empty/invalid |
| KH-R2 | — | Cross-process merge | Concurrent writers can lose updates | **Rejected** — documented non-goal; atomic last-writer-wins |
| KH-R3 | — | `../host` tokens | Path-like hosts stored as map keys | **Rejected** — not joined as filesystem paths; regression asserts store path only |
| KH-R4 | — | russh `check_server_key` | Typed `HostKeyMismatch` collapsed to `bool` | **Rejected** — russh handler API limit; hook still returns typed error for direct callers |

## Simplify deltas (after adversarial)

- Removed unused `Default` on `KnownHostsStore` (empty path trap).
- Collapsed redundant `normalize_host_only` branches.
- TOFU uses `insert_pin` after one validation (no double `pin` validate); dropped redundant save-time re-validation.

## Regression coverage added

- C# empty-bytes fingerprint golden vector
- Soft-fail corrupt lines + invalid UTF-8
- Hostile host/fingerprint rejection
- Mismatch never overwrites disk
- Atomic overwrite of existing file
- TOFU save-failure memory rollback
- Path-like host is map key only
- Existing TOFU / RejectMismatch / accept_server_host_key tests retained

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
```

**Result (final):** known_hosts 17 unit tests pass in both feature modes; full crate suite green (client + auto_sudo + auth when default features on).

## Gate confirmation

- Adversarial clean passes: **2** (independent lane orderings; renewed after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
