# File transfer and external editors

Choose **SFTP** in Quick Connect or the connection editor. It uses port 22 by
default, SSH password/key credentials, host-key verification, inherited folder
credentials, and the effective VPN route. Protocol value 7 is stored in the
existing unrestricted integer column; no schema or data migration is required.

An SSH tab's **Open file transfer in new tab** action opens a separate SFTP
subsystem on its authenticated transport. Each tab owns its directory requests,
transfers and subsystem; the transport and tunnel remain alive until the last
tab closes. SFTP-only connections never request a PTY or shell and are excluded
from MCP terminal inventory and control. Duplicating a connected SFTP tab also
reuses its authenticated transport.

Both panes have independent lazy directory trees, file lists and resize handles.
Each tree starts at its pane's current directory and shows only its descendants.
Navigating up or to another path changes that root without reading its ancestors.
Trees use the same Name, Size and Modified columns as the file lists, with headers
that remain visible while scrolling.
Each Tree and file list has a search icon at the top right of its section.
Click it to replace the column headings with a focused search field. The close
button or Escape clears that filter and restores the headings and sort order.
Tree searches filter the expanded folders and retain ancestors of matches;
they do not fetch additional directories. All four filters work independently.
Click Name, Size or Modified to sort either view; click again to reverse the
direction. Each view retains its own order. Trees sort siblings within each
folder, preserving expanded branches and keeping the current folder visible.
The directory tree icon is highlighted while its tree is visible. Use it to show
or hide the tree, Swap panels to reverse the panes, and Queue to collapse
transfers. The persistent default order is in Settings > File
transfer. Tree requests have independent correlation, at most four concurrent
reads shared by both panes per session, with up to 128 additional queued requests,
the existing 4,096-entry limit and remote listing timeout. Refreshes wait for
in-flight reads of the same folder before requesting a replacement listing.
The tree cache retains up to 128 directory listings, protecting the current root
and in-flight requests from eviction.

Use the checkboxes in either pane to select files and folders. Checkbox clicks
add or remove one item; Shift-click selects a range. Clicking a row leaves the
selection unchanged, and double-clicking still opens folders and local files.

Within File transfer, Tab switches panes; Enter opens a focused directory;
Backspace or Alt+Up goes up; F5 copies to the other pane; F2 renames; F7 creates
a folder; Delete asks before deleting; Ctrl/Cmd+R refreshes; F4 edits a file.
Text fields retain their normal editing shortcuts. F6 move is deferred: copying
does not delete its source. Tree folders and list folders accept transfer drops.

Configure editors in Settings > File transfer. Arguments are individual argv
entries, one per line; `{file}` occupies a complete argument. File patterns use
semicolon-separated globs. The automatic editor chooses Notepad++/Notepad,
macOS's default text editor, or a detected Linux GUI editor. System default is
also available. AppImage library variables and injected PATH are removed when
launching an editor. Local files open directly. Regular remote files download to
`<user data>/sftp-edit/<random id>/files/<original name>`; their journal stays
separate so every supported original filename is preserved.

All editor launches, including the system application, strip inherited Bitwarden
session and password variables using the same filter as the native RDP helpers.

Working directories have POSIX mode 0700 or an inheritable user-only Windows
DACL. Working files and journals use mode 0600. Files stay byte-exact. The Go
watcher observes saves independently of editor process exit, debounces them,
checks the remote size and mtime, and uploads through a sibling temporary file
and atomic rename, retaining permissions. A server that cannot replace via
rename leaves the original and working copy intact and reports an error.

Conflicts offer overwrite, save as a new remote path, or confirmed re-download.
Pending edits wait behind transfers and retry after automatic reconnect to the
same authenticated server and VPN route. Closing with pending changes offers to retain copies
for recovery. Closing also retains clean copies because the external editor can
save again later; use Stop editing or Discard to explicitly remove a copy.
A startup notice and the File transfer
settings list expose recovered copies. Reconnect to the original server/account
and choose Recover in its tab, or reveal/discard the copy. Dirty copies are
never removed as part of ordinary disconnect/error cleanup.

The directory lives under the app's user-data root, so removal of the complete
application data also removes working copies. Ordinary uninstall/data-retention
policy is unchanged; retained data can contain recovered edits.

## Verification

Run `npm run test:sftp-state`, `npm run test:quick-connect-state`, the static
checks and `npm run test:electron`. The SFTP tests include real Chromium/React
surfaces and enforce the project's 80% V8 coverage threshold for the new
components, including their nested callbacks. Node's coverage measures tree
state, routing and IPC contracts.
Go tests use in-process SFTP servers, including an SSH server that rejects shell
and PTY requests, and cover shared lifetime, credentials, backup protocol,
listing bounds, editor argv/environment, save debounce, conflicts and recovery.

Node coverage excludes TSX and Electron's main/preload entrypoints, following
`scripts/test-coverage.ts`; mounted Chromium tests and source-contract tests
cover those boundaries. Platform ACL/syscall failure branches cannot all be
forced portably. Real Notepad++/Notepad, TextEdit/VS Code, gedit/Kate, chrooted
OpenSSH and VPN-provider interoperability remain manual checks on their target
platforms.

Remote conflicts are checked again immediately before rename. SFTP does not
provide a portable compare-and-swap rename, so another writer can still race in
the final stat/rename interval. Save-as uses a no-replace rename and changes the
watched destination only after the new file has been created. File operations
have a 30-second deadline and close only the affected tab's subsystem on timeout.
Unchanged files are polled by metadata, with a periodic hash check for editors
that preserve timestamps; unchanged states do not generate repeated events.
