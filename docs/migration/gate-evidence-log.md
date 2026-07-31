# Surface-lab gate evidence log

Companion to [gate-checklist.md](gate-checklist.md). Tracks **honest** evidence
status per gate — **not** a substitute for hardware sign-off.

## Status values

| Status | Meaning |
|---|---|
| `Pending` | No lab smoke / no evidence recorded yet |
| `LabOnly` | `surface-lab` smoke or partial path exists; **does not** satisfy gate-checklist |
| `HardwarePass` | Demonstrated on real hardware with evidence pack (recording, DPI matrix, SHA) — **never claim from lab alone** |

**Rule:** Lab smoke ≠ hardware pass. Do not tick gate-checklist x64/ARM64 boxes from this log unless status is `HardwarePass` for that architecture.

## Log (gates 1–8)

Pre-filled `LabOnly` where surface-lab has a smoke / partial module. Date is the
log stub date, not a hardware run. Machine arch left blank until a real machine
is recorded. **No row claims `HardwarePass`.**

| Gate | Status | Date | Machine arch | Notes |
|---:|---|---|---|---|
| 1 | LabOnly | 2026-07-31 | — | `gate01_window` + `gpui_host` (`--features gpui`): title bar / theme / Mica / DPI helpers. Hardware 100/150/200% matrix still required. |
| 2 | LabOnly | 2026-07-31 | — | `gate02_panes` + optional `pane-layout` broker sink. 2×2 splitters in lab; tab DnD is stub. |
| 3 | LabOnly | 2026-07-31 | — | **Kill switch.** `gate03_webview2` wry child smoke (`--features webview`). Not a movable-pane hardware pass. |
| 4 | LabOnly | 2026-07-31 | — | **Kill switch.** `OverlayStackController` hide-on-chrome policy smoke; GPUI popup wiring still TODO. |
| 5 | LabOnly | 2026-07-31 | — | **Kill switch.** `gate05_xterm` Assets/web or echo stub (`--features webview`). Clipboard / focus soak still lab-partial. |
| 6 | LabOnly | 2026-07-31 | — | **Kill switch.** `gate06_rdp_activex` owned-overlay OLE smoke (`--features rdp`); live connect via `--gate06-live`. Not a hardware COM/reconnect pass. |
| 7 | LabOnly | 2026-07-31 | — | **Kill switch.** `FocusBroker` / `FocusCycle` policy smoke (always on). Live GPUI↔RDP↔WebView2 handoff unproven on hardware. |
| 8 | LabOnly | 2026-07-31 | — | **Kill switch.** A11y checklist hooks + AccessKit spike (`--features gpui`). Inspect/Narrator hardware evidence still required. |

## How to upgrade a row

1. Run the gate on **real** x64 and/or ARM64 hardware (see evidence pack in [gate-checklist.md](gate-checklist.md)).
2. Attach recording / screenshots / log snippet / `surface-lab` commit SHA.
3. Set status to `HardwarePass`, fill date + machine arch, and only then tick the matching cell in [gate-checklist.md](gate-checklist.md).
