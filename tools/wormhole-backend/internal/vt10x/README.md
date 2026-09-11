# Terminal parser provenance

This package contains the core emulator files from
[ActiveState/vt10x v1.3.1](https://github.com/ActiveState/vt10x/tree/v1.3.1),
under the accompanying MIT license. Unused PTY/expect, strip and command-line
helpers are omitted. The parser remains portable and is shared by SSH and serial.
The upstream state, CSI, string and in-memory VT tests are retained; the PTY
integration test is omitted with its unused helpers. The state test uses the
maintained `stretchr/testify` assertions instead of the old `autarch` fork.

The upstream API does not expose saved cursor state. Keeping the core locally
lets us fix it at the source without duplicating cursor/rendition parsing in the
SSH observer or accessing private fields through reflection.

Local changes in `state.go`:

- Store DECSC/DECRC cursor state separately for the normal and alternate screens,
  including rendition and origin flags, and reset both slots on RIS.
- Save the normal cursor before entering mode 1049 and restore it after leaving.
- Switch buffers only when the requested mode differs from the current one, so
  redundant exits cannot activate the alternate screen.
- Follow each mode's clear semantics: mode 47 preserves alternate content,
  1047 clears it on exit, and 1049 also clears it on entry.
- Resize each viewport around its own cursor, moving and clamping both saved
  cursors with their text so a later grow cannot resurrect stale coordinates.
- Reset both viewports completely on RIS, including rectangular terminal sizes.

`cursor_test.go` and the backend terminal regression suite exercise these changes.
Unmodified imported code is third-party code, excluded from the new/modified-code
coverage requirement; local changes must meet the usual 80% threshold. The full
backend coverage profile still includes this package. Keep changes focused and
compare against v1.3.1 when updating it.
