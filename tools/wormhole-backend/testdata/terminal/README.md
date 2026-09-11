# nano scrolling capture

`nano-scroll.json` is raw stdout captured from GNU nano 7.2 (Git for Windows),
with `TERM=xterm-256color` and an 80 by 24 terminal. It contains only synthetic
text in a file named `example.txt`.

Capture procedure:

1. Generate 300 lines: `Line NNN: ` followed by 51 letters, where letter `j` on
   line `n` (1-based line, 0-based letter) is `A + ((13*n + j*n) % 26)`.
2. Run `nano --ignorercfiles example.txt`, redirecting stdout to a capture file
   while keeping stdin attached to the terminal.
3. Send Down 23 times, Down another 23 times, Page Down once, then Page Down
   four more times, allowing nano to redraw between each group.
4. Exit with Ctrl+X and encode stdout as the JSON `output` string without
   changing its bytes.

The capture includes ncurses' `ESC 7`, scrolling-region change, `ESC 8`, and
`CSI 4 S` scroll sequence, followed by later page redraws and the `1049l` exit.
With upstream vt10x v1.3.1, the editor's cursor save overwrites the shell's saved
cursor. The replay test checks the restored screen, cursor, scrollback, terminal
modes and subsequent shell output across packet boundaries and repeated editor
sessions. It runs without requiring nano or a live SSH server.
