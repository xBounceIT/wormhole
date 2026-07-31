# Adversarial ledger — connection node change Fake pub/sub (`wormhole-domain`)

**Scope:**
- `rust/crates/wormhole-domain/src/connection_node_change.rs` (+ re-exports in `lib.rs`)
- `rust/crates/wormhole-domain/tests/connection_node_change_tests.rs`
- Docs: `02-domain.md` (notifier section), `feature-matrix.md` Inheritance / live-refresh row (Spike)

**Out of scope:** GPUI tree/session subscribers; SQLite write-path publishers; C#
`IConnectionNodeChangeNotifier` production wiring; live WinUI refresh.

**Authority:** full adversarial-review-fix (edit in scope; no git commit/push)  
**Compared against:** C# `IConnectionNodeChangeNotifier` / `ConnectionNodeChangeNotifier`
(update-only full-node clone) — Rust extends create/update/delete/reparent as
**metadata-only** events  
**Baseline:** `cargo test -p wormhole-domain --test connection_node_change_tests` — 7 green  
**Final:** **16** passed (`cargo test -p wormhole-domain` full suite green)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-domain` | **pass** |
| `cargo test -p wormhole-domain --test connection_node_change_tests` | **pass** (16) |

---

## Accepted findings

### NC-01 — Subscription id collision at `u64::MAX` (`P2`) — **fixed**

- **Where:** `FakeInner::next_id` / `subscribe`
- **Invariant:** Each active subscription has a unique id; `unsubscribe` removes exactly one
- **Evidence:** `saturating_add(1)` stuck at `u64::MAX` minted duplicate ids; one unsubscribe dropped all collisions
- **Impact:** Lab hosts sharing the Fake could silently lose unrelated listeners
- **Fix:** `mint_subscription_id` wraps, skips `0` (Nop sentinel), skips ids still live
- **Regression:** `subscription_ids_skip_collision_at_u64_max`

### NC-02 — Nested publish reordered delivery for later subscribers (`P2`) — **fixed**

- **Where:** `FakeConnectionNodeChangeNotifier::publish`
- **Invariant:** Delivery order matches the recorded event log for all subscribers
- **Evidence:** Callback A nested `publish_updated` during Created fan-out; subscriber B saw Updated before Created
- **Impact:** Tree/session hosts could refresh profile for a node before observing create
- **Fix:** Nested publishes enqueue; drain after current fan-out completes
- **Regression:** `nested_publish_preserves_delivery_order_for_later_subscribers`

### NC-03 — Concurrent publish could strand nested events (`P1`) — **fixed**

- **Where:** `publish` end-of-fan-out `dispatching = false`
- **Invariant:** Every recorded event is delivered to current subscribers
- **Evidence:** TOCTOU between `pending.pop_front() == None` and clearing `dispatching` let another thread enqueue then leave the queue undrained
- **Impact:** Lost fan-out under concurrent publishers (Clone/`Arc` Fake)
- **Fix:** Clear `dispatching` only under the same lock hold that observes an empty pending queue
- **Regression:** `concurrent_publish_delivers_every_recorded_event`

### NC-04 — Pub/sub + hint contracts under-pinned (`P2`) — **fixed**

- **Where:** tests + rustdoc
- **Invariant:** Mid-publish subscribe misses current event; `*_from_node` strips to metadata; hint negatives; Display labels; idempotent unsubscribe; `clear` is log-only; Shared/`dyn` Publisher helpers work; Reparented (not Updated) for structural moves
- **Evidence:** Gaps vs Fake contracts and C# `ApplyConnectionNodeUpdated` patch semantics
- **Fix:** Focused regressions + rustdoc / `02-domain.md` notes
- **Regression:** `mid_publish_subscribe_misses_current_event`, `from_node_helpers_and_hint_negatives`, `change_kind_display_labels`, `unsubscribe_is_idempotent_and_clear_keeps_subscribers`, `multi_subscriber_fanout_is_insertion_order`, `shared_notifier_publisher_helpers_work`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Catch panicking callbacks — same as C# multicast; out of Fake contract |
| REJ-02 | — | Bound recorded `events` Vec — Lab Fake inspection log; hosts can `clear` |
| REJ-03 | — | Add `publish_created_from_node` siblings on Publisher — C# only had update; Event helpers suffice |
| REJ-04 | — | Share id-mint with surface-win broker — different ownership model; avoid cross-crate churn |
| REJ-05 | — | Wire GPUI tree/session subscribers — explicitly Pending / out of scope |
| REJ-06 | — | Forbid public fields forging `previous_parent_id` on Created — constructors are the API; mirrors other domain POD events |
| REJ-07 | — | Private constructor helper for four event factories — taste-only duplication |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → Fake id mint → test resistance | NC-01, NC-04 | Fixed; reset |
| Adv-2 | Concurrency → reentrancy order → security metadata | NC-02 | Fixed; reset |
| Adv-3 | Reverse: race on `dispatching` clear → integration | NC-03 (+ clear rustdoc) | Fixed; reset |
| Adv-4 | Tests-as-oracles → Reparented footgun docs → security | None | Clean (1/2) |
| Adv-5 | Perf Fake bounds → Publisher asymmetry → public fields | None (rejected) | Clean (2/2) |
| Post-simplify Adv-R1 | `RecordingRefreshListener` single-mutex delta | None | Clean (1/2) |
| Post-simplify Adv-R2 | Nested queue + concurrent delivery still hold | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Three Mutexes on `RecordingRefreshListener` → one state lock | One lock per callback | Atomic event+hint record | **Fixed** → reset (+ adv re-run) |
| 2 | Shared mint/helpers stable; reject Event ctor merge | No hot-path I/O | Nested queue + concurrent clear intact | Clean (1/3) |
| 3 | No missed local helpers | Snapshot-per-event necessary | Diff hygiene / docs | Clean (2/3) |
| 4 | Same | Same | Ledger / README | Clean (3/3) |

Simplify cycle 1 changed code → post-simplify adversarial re-run completed clean; Sim-2…4 clean with no further edits.

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Metadata-only / no secrets in event or Fake Debug | `updated_from_node` strips host/username/name; Fake Debug is counts-only |
| Create / update / delete / reparent surface | Recorded + Publisher helpers; refresh hints match kinds |
| Nested publish without deadlock | Lock released before callbacks; nested queued |
| Concurrent Clone publishers | All recorded events delivered |
| Subscription id uniqueness | Wrap + skip 0 + skip live ids |
| Nop swallow | Subscribe returns 0; never invokes; unsubscribe false |
| C# update patch vs Reparented | Documented: parent moves must use Reparented |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-domain --test connection_node_change_tests
cargo test -p wormhole-domain
```

Expected: connection_node_change **16** passed; full `wormhole-domain` green.
