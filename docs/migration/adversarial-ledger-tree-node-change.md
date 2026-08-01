# Adversarial ledger — Tree node-change subscriber glue

**Scope:** `rust/crates/wormhole-ui/src/tree/node_change.rs` (new) + registration /
re-exports in `tree/mod.rs` and the crate-root `pub use tree {…}` block in `lib.rs`.

**Out of scope:** GPUI tree chrome; live data loading (glue never loads — sink
decides); `wormhole-domain` notifier internals (read-only reference crate);
session-tab profile refresh application.

**Compared against:** C# `ViewModels/ConnectionTreeViewModel.cs` (subscribe +
`RefreshAsync` vs `ApplyConnectionNodeUpdated`, folder-descendant refresh) and
`Services/IConnectionNodeChangeNotifier.cs`; Rust `wormhole-domain::connection_node_change`
(`suggests_tree_reload` / `suggests_session_profile_refresh` / `may_affect_descendant_sessions`).

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** module **16** tests  
**Final:** module **27** tests; wormhole-ui lib **443** / **17** doc / **5** integration

**Attack focus:** subscribe race (two-phase check→register→store), stale callback
delivery after unsubscribe→resubscribe, drop/unsubscribe idempotence, poison recovery,
nested publish ordering, re-entrant sink, deadlock lanes (unsubscribe-from-sink),
Nop-notifier sentinel, unknown ids, Debug leakage of node ids.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (+ re-pass on simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui` | **pass** (443 lib) |
| `cargo check -p wormhole-ui` | **pass** (only pre-existing warning) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F1 | P1 | `subscribe()` two-phase race could lose/duplicate events under concurrent subscribe+publish | Single-phase: state lock held across `notifier.subscribe`; race-retry branch removed |
| F2 | P2 | Stale callback from a superseded registration delivered after unsubscribe→resubscribe | Per-registration `epoch` in the liveness check |
| F3 | P3 | `FakeTreeRefreshSink` Debug printed node ids | Redacted to call count |
| F4 | P2 | Poison recovery untested | 2 tests: glue state + sink mutex poisoned → both recover and keep delivering |
| F5 | P2 | Race lanes untested | subscribe×publish, unsubscribe×publish, drop-mid-publish thread-smoke tests |
| F6 | P2 | Sink-driven nested publish untested | `ReentrantSink` test (record order + no deadlock) |
| F7 | P3 | Nop-notifier sentinel lifecycle untested | Test added |
| F8 | P3 | Doc/lifecycle wording + subscribe lock-contract | Documented |
| C2 | P3 | Unsubscribe-from-inside-sink (deadlock lane) | `UnsubscribingSink` test |
| C3 | P3 | Doc-table rows Deleted(folder) / Reparented(connection) unpinned | 2 tests |
| S1 | P3 | Redundant public API `total_count()` == `len()` | Removed |

### Rejected candidates

Callback-invoked-inside-`subscribe` deadlock (out-of-contract, documented); notifier
invoking callbacks while holding its own lock (contract says lock released before
call); sink panic propagating to publisher (C# parity).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-ui tree::node_change
cargo test -p wormhole-ui
```

**Counts:** node_change **27/27**; full wormhole-ui lib **443**.