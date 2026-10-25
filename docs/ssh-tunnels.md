# SSH tunnels (jump hosts)

In the tunnel editor, select **SSH tunnel (jump host)**. Choose a saved SSH connection
to reuse its host, username, credential, folder inheritance and route. Alternatively,
choose **Manual** and enter a host, port, username and local saved SSH credential.
Assign this tunnel through the existing route selector on a connection or folder.
SSH, RDP, VNC, HTTP and HTTPS use the same SOCKS route.

Local passwords, private keys and encrypted private keys, including PKCS#8, are supported.
Select an optional OpenSSH user certificate in the saved SSH key credential editor.
The certificate must match the key and be valid; it can be renewed independently.
The shared SSH signer parser applies the same rules in ordinary SSH sessions and tunnels.
See [SSH authentication](ssh-authentication.md) for supported formats and protected storage.
Bitwarden credentials are currently rejected for jump hosts. Passphrases that are
not saved, and keyboard-interactive/OTP challenges, use the tunnel's secret prompt.

The first connection displays the jump host's SHA-256 fingerprint and requires
**Trust**. Verify it independently with the administrator. The backend persists the
approved pin in the saved SSH connection (or manual tunnel settings). The sidecar
requires an exact pin and never accepts a key on its own. A changed key blocks the
tunnel; verify the change before using **Forget pin** and saving. Forgetting a saved
connection's pin also changes that connection's trust. Closing the editor without
saving leaves its pin intact. A handshake changing between the probe and sidecar
authentication is rejected as well.
Saving an older editor preserves the backend's latest trust and cannot restore a revoked
pin. Concurrent approvals and editor saves are serialized across backend processes, so
a failed save cannot roll back another connection's approved fingerprint.

A saved jump connection may itself use a VPN or another SSH tunnel. Chains are
limited to three tunnel hops, including the final VPN hop. Cycles and missing
references fail before establishment. Each upstream lease remains held until its
downstream sidecar exits; leases are released from the target back to the upstream.
Concurrent sessions in a backend share the established tunnel. New leases resolve
the current connection, inherited credential and upstream settings, so credential
rotation cannot reuse a stale tunnel. Active sessions keep their existing lease.
Runtime cache identities use a random process-local key and are never persisted.
Changing credentials, host-key trust or the upstream configuration during authentication
cancels the pending start. Reconnect to use the updated configuration. Cancelling a lease
also stops its pending network requests and authentication prompts.

The sidecar exposes SOCKS5 only on `127.0.0.1`, forwards destination DNS names to SSH,
and sends OpenSSH keepalive requests (default 30 seconds, range 1–3600). A broken
SSH connection, failed keepalive or lost upstream closes the sidecar and dependent
sessions. There is no direct fallback. Secrets travel through protected storage
and stdin, never tunnel settings, command arguments or diagnostics. Only explicit
`--mock` tests bypass SSH.

Backups preserve node, credential and tunnel IDs, so the reference-only settings
need no remapping. Missing references in an imported backup remain readable and
produce a connection error. Deleting a referenced jump connection or credential is
blocked with the referencing tunnel's name. VPN profile-file imports do not create
or remap SSH connection IDs.
Deletion is serialized with tunnel edits and node credential or ancestry changes, so an
in-flight save cannot bypass reference checks, including inherited credentials.

The portable Go sidecar is included in Windows x64/arm64, Linux and macOS builds
(including the native universal build). CodeQL and coverage discover its Go module
and the shared `tools/internal/sshauth` module automatically. The sidecar is staged
alongside the other native binaries; platform signing requires the release environment.

Regression coverage uses Go statement profiles, Node loaded-module coverage and a
Chromium test measuring the mounted SSH editor. Process entrypoints and PowerShell
release scripts follow the project's coverage exclusions; packaging contracts and
cross-compilation check the sidecar's inclusion and architecture selection.
The rollback regression uses two Windows processes and DPAPI. Other platforms use a
process-local protected-store fake in tests; native lock contention and cancellation
tests run on every platform.
System RDP controller dispatch is tested on Windows, where that client is supported;
the external-process supervisor fixture runs on all platforms.
