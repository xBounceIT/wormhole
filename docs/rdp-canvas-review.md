# RDP canvas review ledger

Scope: the uncommitted macOS canvas implementation; FreeRDP provisioning is
owned by a separate change. Windows ActiveX and Linux embedding remain intact.

## First adversarial cycle

All eight lanes inspected: behavior, boundaries, atomicity, lifecycle, privacy,
integration, performance and test resistance. Baseline: 30 focused tests passed.

| ID | Severity | Location and reproduced failure | Fix and regression | Status |
| --- | --- | --- | --- | --- |
| R1 | P1 | `tools/wormhole-freerdp-host/register.cmake:3`: real configure fails with “Subdirectories may not be created during deferred execution” | Register the target directly; execute real CMake in the build test | fixed |
| R2 | P1 | `main.c:handle_command`: repeated show clears an outstanding frame acknowledgement; an old acknowledgement releases a newer paint after hide/show | Number paints and match acknowledgements; test native flow transitions | fixed |
| R3 | P1 | `RdpCanvas.tsx`: queued input resolves lifecycle at send time, so input queued for an old connection can enter its replacement | Capture lifecycle when enqueued; discard queued input on blur and release after transport failure | fixed |
| R4 | P1 | `rdp_framebuffer.go:writeFramebuffer/startFramebufferRdp`: synchronous writes to a non-reading child can block the controller and prevent disconnect | Bound pipe writes and terminate a stalled adapter; blocked pipe regression | fixed |
| R5 | P1 | `rdp_framebuffer.go:startFramebufferRdp`: strict certificate profile still enters the accept-once prompt | Pass FreeRDP's deny policy for strict embedded profiles; policy regression | fixed |
| R6 | P2 | `main.c:handle_command/channel_connected`: resize precedes server display caps, ignores advertised area, and pending geometry is lost before channel setup; clipboard advertises before MonitorReady | Negotiate before sending, retain latest size and bound display area; native policy tests | fixed |
| R7 | P1 | `electron/main.ts:rememberRdpSurfacePlacement`: another window can replace the owner with resize and receive frames/send input | Check existing ownership on every surface operation; ownership regression | fixed |
| R8 | P2 | `rdp_framebuffer.go:encodeRdpFramebufferCommand`: Go accepts 16384-square resize rejected by the native parser | Clamp display-control requests consistently to 8192 per dimension; boundary regression | fixed |

Rejected candidates: zero physical monitor dimensions are explicitly ignored by
[MS-RDPEDISP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp/ea2de591-9203-42cd-9908-be7a55237d1c),
not protocol errors. Missing channel loading is false: FreeRDP's common client
installs LoadChannels. Prototype keyboard properties are not reachable native
keyboard codes and fail IPC validation. Static cursor customization is outside
this embedding correction. Clipboard thread races were not established.

Native macOS linking, AppKit clipboard and a real RDP login still require a Mac.
Synthetic renderer tests and FreeRDP header checks do not substitute for them.

## Second adversarial cycle

Reviewed from native state to Go, IPC and the mounted renderer, through all eight
lanes. R2 follow-up: a connected event can enable React after an initial paint
was discarded. An already-visible `show` must request a full repaint, while
preserving the outstanding acknowledgement. Native transition test added.
Other first-cycle fixes passed 35 tests, Go regressions, real Electron mounting
(91.4% callback blocks) and the FreeRDP 3.33 header compatibility check.

## Third adversarial cycle

All eight lanes inspected against the complete test suite and FreeRDP's real
reconnect implementation, then the following fixes applied:

| ID | Severity | Evidence / location | Fix and regression | Status |
| --- | --- | --- | --- | --- |
| R9 | P2 | `electron/main.ts` certificate prompt bypassed `showCoordinatedMessageBox`; existing shell lifecycle regression failed | Reuse the existing native-dialog coordinator; retain the existing assertion | fixed |
| R10 | P1 | `main.c:confirm_certificate` rejected hide without cancelling FreeRDP's internal reconnect loop; a delayed answer could be consumed by a later prompt in the same lifecycle | Make certificate cancellation terminal, abort connect, and refuse subsequent replies; native state regression tests cancel then delayed accept | fixed |

## Closure reviews

- Adversarial clean cycle 1: native-to-renderer review of all eight lanes after
  R9/R10. Checked reconnect cancellation, paint sequence wrap, bounded input
  batches, channel readiness, timer shutdown, owner routing and build target
  registration. No new accepted findings.
- Adversarial clean cycle 2: reverse traversal from regression tests and preload
  callers to Go/native. Checked lock/remount, old acknowledgements, strict trust,
  protocol sizes, missing helper behavior, packaging paths and other platforms.
  No new accepted findings.
- Iterative simplify cycle 1: reuse, efficiency and quality passes over the
  controller/adapter/canvas. No findings; cross-language validation remains
  intentional, and the native-dialog coordinator is reused.
- Iterative simplify cycle 2: the three passes over lifecycle, cleanup and hot
  paths. No findings; bounded batches and tile acknowledgements avoid unbounded
  queues, and pending input preserves its lifecycle.
- Iterative simplify cycle 3: the three passes from tests and public contracts
  back to implementations. No findings. Avoided unrelated abstractions and
  speculative framebuffer optimizations. No implementation changes in these
  three cycles; the latest two clean adversarial cycles remain valid.

Measured focused coverage: TypeScript contracts/input/certificate helpers 100%
lines; build orchestration 95.35%; native wire and state policies 100% lines;
Go framebuffer adapter 153/167 statements (91.6%); mounted canvas callbacks
93.4% V8 blocks, with RdpSurface at 100%. Native library callbacks, AppKit and universal linking require
macOS integration coverage and are explicitly excluded from these figures.

## Final suite fixture correction

R11 (P2, fixed): the pre-existing `tests/fixtures/auth-prompt.tsx` RDP layout
fake omitted the new event/input bridge and still asserted an empty surface.
The mounted component therefore threw before its geometry effect. Updated the
fake to the actual bridge contract and require exactly one canvas, no overlay
buttons, unchanged full-surface bounds and zero subscriptions after unmount.
Production code is unchanged by this fixture correction.

The layout scenario now runs in `tests/fixtures/rdp-canvas.tsx`, bundled with
production imports and CSS. Its old function-body extraction was removed from
`tests/auth-prompt.test.ts`; all geometry/visibility/cleanup assertions were
retained. Both mounted suites pass independently. Rechecked all eight attack
lanes twice after this test-only correction, then three reuse/efficiency/quality
cycles on the final test wiring and complete scope: no additional findings.

## Final verification

- Focused Node/C regressions: passed, including real CMake configuration.
- `npm run test:electron`: the first runs exposed R9 and R11. After fixes,
  every section passed: preceding sections in the full invocation, the two
  corrected mounted tests individually, and all remaining npm test sections
  (list-search through sidecars) sequentially. No assertion was removed without
  retaining its coverage in the canvas fixture.
- `go test ./...`: passed for the backend, and all sidecar modules passed via
  the Electron suite. Focused Go coverage is recorded above.
- `npm run typecheck`, `npm run lint`, `npm run format:check`,
  `npm run build:renderer`, `npm run build:electron`: passed.
- FreeRDP 3.33 header compatibility compile and `git diff --check`: passed.
- Existing environment notices: Windows skips the POSIX execute-bit test;
  Node reports experimental TypeScript API warnings; Git reports its global
  ignore file access and package.json LF/CRLF warnings. No new functional warning.
- Outstanding external verification: universal macOS link/package, AppKit
  clipboard, and an actual macOS RDP connection. This Windows host cannot certify
  those results. FreeRDP provisioning remains outside this change.

## CI integration correction

The first native CI run found that vcpkg's ARM manifest install removed the Intel
SDK from the shared install root. Preserve a separate dependency root per triplet
so the later canvas build can reuse both configured FreeRDP trees. Updated license
staging and added a regression modeling manifest synchronization across both builds.
The 12 build tests pass, including real CMake configuration; build script coverage
is 99.08% for the runtime and 95.35% for the canvas adapter. Reuse, efficiency, and
quality simplify passes found no further justified changes. Native CI must validate
the actual universal adapter link after this correction.
