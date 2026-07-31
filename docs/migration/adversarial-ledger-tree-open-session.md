# Adversarial ledger — Tree Open → session connect (`wormhole-ui`)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/tree/open.rs` (+ `tree/mod.rs` / crate-root re-exports)
- Related unit tests (`MemoryConnectionSource` + Fake serial/SSH/HTTP + FakeCredentialResolver)
- `docs/migration/17-tree-settings-vm.md`, `docs/migration/16-session-orchestrator.md` (caller table), README ledger link
- this ledger

Out of scope: GPUI TreeView / tab factory; Quick Connect ephemeral path internals (sibling); HardwarePass / cutover; unrelated tunnel-provider churn from parallel agents.

**Attack focus:** folder connect; inheritance skip; password on `ConnectRequest` / `TreeConnectRequest` Debug; missing id; double-open; RDP/VNC `UnsupportedProtocol`; source / resolve errors; selection short-circuit; `options_with_password` blank; crate-root alias coherence (`connect_tree` / `connect_tree_prepared` vs QC `connect_prepared`).

Baseline (before review edits): `cargo test -p wormhole-ui --lib tree::open` — 14 tests green on enriched API; full lib suite green prior to parallel tunnels noise.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TO-001 | P2 | `options_with_password` | Doc claimed empty → `None` but `Some("")` / whitespace preserved | Doc vs impl; SSH blank password risk | **Fixed** — trim; blank/whitespace → `None` + regression |
| TO-002 | P2 | `TreeOpenError` / tests | Source `list_all` failure path unpinned (fail-closed vs orchestrator) | Attack: source errors | **Fixed** — `FailingConnectionSource` + never-hits-orch assert |
| TO-003 | P2 | prepare / resolve | `MissingHost` / `MissingProtocol` fail-closed unpinned | Attack: incomplete connection | **Fixed** — Resolve regressions |
| TO-004 | P2 | inheritance | Leaf host + `tunnel_enabled=false` skip unpinned | Attack: inheritance skip | **Fixed** — host override + tunnel off (config id still inherits, domain parity) |
| TO-005 | P2 | `connect_from_tree` | Double-open contract unpinned | Attack: double-open | **Fixed** — two handles, distinct ids, `open_count==2` |
| TO-006 | P2 | `TreeOpenError::Session` | Unused `Session` variant implied connect failures wrap into `TreeOpenError` | Connect returns Failed on handle (docs) | **Fixed** — removed unused variant |
| TO-007 | P2 | `ConnectRequest::with_options` | Did not force `is_ephemeral = false` (unlike `with_password` / `from_profile`) | Hostile profile mutation | **Fixed** — force false + regression |
| TO-008 | P3 | selection `connect_from_selection` | Folder short-circuit covered at prepare only | Attack: selection folder | **Fixed** — folder assert also on `connect_from_selection` |
| TO-009 | P3 | docs / ledger | Enriched API + blank-password / handle-failure semantics under-documented; ledger missing | Policy | **Fixed** — `17-tree-settings-vm.md`, README, this ledger |
| TO-010 | — | Merge tree/QC `connect_prepared` names | Crate-root clash risk | Aliases `connect_tree` / `connect_tree_prepared` | **Rejected** — intentional parallel to QC; aliases keep crate root coherent |
| TO-011 | — | Dedupe double-open at glue | Tab bar rejects duplicates | Orchestrator allocates new session ids | **Rejected** — tab dedupe is host/`SessionTabBarState`; glue must allow two handles |
| TO-012 | — | Clear `tunnel_config_id` when tunnel off | Leaf `tunnel_enabled=false` still inherits config id | Domain parity tests | **Rejected** — `TunnelEnabled` gates launch; config id inherits by design |
| TO-013 | — | Normalize password inside `with_options` | Bypass blank filter via raw `ConnectOptions` | Caller owns full options | **Rejected** — blank filter is for password-field stub only |

## Fixes applied

- `options_with_password` blank/whitespace → `None` (trim)
- Drop unused `TreeOpenError::Session`; protocol failures stay on `SessionHandle`
- `with_options` / `with_password` / `from_profile` unified: password helpers route through `with_options`; always `is_ephemeral = false`
- `connect` / `connect_from_tree` route through `connect_prepared` (one orchestrator entry)
- `fake_orchestrator_for_tests` reuses `fake_orchestrator_with_credentials(FakeCredentialResolver::new())`
- Regressions: blank password, inheritance skip, source/resolve fail-closed, double-open, selection folder connect, Debug redaction, RDP/VNC secrets, CredMgr stub path
- Docs + single ledger + README index

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TO-001…006, TO-008…009 | Fixed; reset |
| Adv-2 | Reverse: Debug/password → ephemeral flag → selection short-circuit → aliases → inheritance | TO-007 | Fixed; reset |
| Adv-3 | Forward on post-fix enriched surface (prepare_tree_*, connect_prepared, crate-root) | None | Clean (1/2) |
| Adv-4 | Reverse: UnsupportedProtocol secrets, CredMgr stub, blank password, double-open, docs ≠ GPUI | None (TO-010…013 rejected) | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `with_password` → `with_options(options_with_password)`; `from_profile` → `ConnectRequest::with_password` | — | Doc on ephemeral force | Yes → reset | Fixed |
| Sim-2 | `fake_orchestrator_for_tests` → `with_credentials`; `connect` / `connect_from_tree` → `connect_prepared` | No hot-path I/O change | Selection folder connect assert; docs | Yes → reset | Fixed |
| Sim-3 | Parallel QC names kept (aliases) | Snapshot `list_all` kept | Diff hygiene / ledger | None | Clean (1/3) |
| Sim-4 | Same | Same | In-scope only | None | Clean (2/3) |
| Sim-5 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: unified `connect_prepared` path, fake orch reuse, blank password, ephemeral force | None | Clean (1/2) |
| Adv-R2 | Reverse on final surface (folder/source/resolve, Debug, RDP/VNC, CredMgr, aliases) | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib
cargo test -p wormhole-session
```

Result: **pass** — `wormhole-ui --lib` **163** ok (incl. **21** `tree::open`); `wormhole-session` **15** lib + **33** orchestrator_fakes ok. Scoped path hygiene clean.

## Residual notes

- GPUI tree Open chrome / tab factory remain non-goals.
- Crate-root `connect_prepared` remains the Quick Connect symbol; tree uses `connect_tree_prepared`.
- Parallel tunnel-provider edits outside this scope may briefly break workspace builds; tree-open glue itself does not depend on those modules at runtime for Fake paths.
