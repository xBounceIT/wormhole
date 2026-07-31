# Surface-lab gate checklist

Executable acceptance for Phase 1. Mark only after demonstration on **real hardware**.

Honest lab-vs-hardware status stubs: [gate-evidence-log.md](gate-evidence-log.md)
(`LabOnly` ≠ pass — do not tick boxes from lab smoke alone).

| Gate | Criterion | x64 | ARM64 | Notes / PR |
|---:|---|:---:|:---:|---|
| 1 | GPUI window: custom title bar, Mica, light/dark, DPI 100–200% | ☐ | ☐ | |
| 2 | Four resizable panes with drag-and-drop | ☐ | ☐ | |
| 3 | WebView2 inside a movable/resizable pane | ☐ | ☐ | **Kill switch** |
| 4 | Menus, tooltips, dialogs correctly above WebView2 | ☐ | ☐ | **Kill switch** |
| 5 | xterm.js bidirectional messaging, focus, resize, clipboard | ☐ | ☐ | **Kill switch** |
| 6 | ActiveX `MsRdpClient9NotSafeForScripting`: COM events, connect, reconnect; **owned overlay** (`GWLP_HWNDPARENT`), not `SetParent`/`WS_CHILD` | ☐ | ☐ | **Kill switch** |
| 7 | Focus handoff GPUI ↔ RDP ↔ WebView2 | ☐ | ☐ | **Kill switch** — [08-focus-a11y.md](08-focus-a11y.md); lab: `FocusBroker` |
| 8 | UI Automation + full keyboard navigation | ☐ | ☐ | **Kill switch** — checklist in `gate08_a11y::KEYBOARD_A11Y_CHECKLIST`; AccessKit via `--features gpui` |

## Pass rule

- Gates **1–2** must pass.  
- If any of **3–8** fails without a sustainable patch, **suspend the GPUI migration** before funding domain porting.  
- “Sustainable” means: no per-frame full-window hacks, no broken a11y forever, no architecture that cannot host four simultaneous native surfaces.

## Evidence pack (per gate)

Attach for each architecture:

- short screen recording or screenshots at 100% / 150% / 200% DPI  
- light and dark  
- log snippet (no secrets)  
- commit SHA of `surface-lab`

## Out of scope until gates pass

- Production cutover / replacing the WinUI Inno installer as default — see [15-cutover.md](15-cutover.md)
- `wormhole-domain` / `InheritanceResolver` port as a cutover blocker (domain crate may land earlier for parity tests)
- VPN control-plane rewrite as the sole host
- Removing the .NET app  
