# Local vault SSH and SFTP sessions

Saved connections and unsaved Quick Connect use the same native SSH recipient.
The ordinary application sends either a saved node reference or public temporary
target metadata, plus terminal dimensions and an optional manual-entry intent.
Passwords, private keys, certificates and key passphrases cannot be supplied by
that IPC. Go validates targets, resolves inheritance and account references,
authorizes the exact VPN route, verifies host identity and seals credentials to
the native recipient key associated with the newly spawned process.

## Admission and ownership

Main reserves the owning document and native session ID before asynchronous
authentication or temporary-target registration. Cancellation joins late work;
reload, renderer loss, lock and shutdown retire the original native cohort.
An explicit synchronous admission receipt transfers responsibility for retiring
the captured Go target. Rejected admissions leave that responsibility with the
original caller. No renderer receives the temporary stage ID or recipient key.

Quick targets are bounded, nonpersistent owner admissions. Their pin is confirmed
through the separate temporary-host operation, including the existing fresh-action
policy. They do not create saved nodes. First-use and changed fingerprints are
probed without authenticating before the credential handoff. A route failure
retires the session; it never retries directly.

One native transport and route can serve its terminal and several SFTP tabs.
Closing the terminal closes only that member while file tabs remain. The original
target and native identity stay reserved until the last member, native process,
route and any credential document have positive shutdown acknowledgements.
Failed cleanup retains the reservation and supports an explicit retry. New input,
resize, clipboard paste, file commands and SFTP sharing capture their member's
generation before waiting for authentication, so queued work cannot reach a
replacement connection with the same ID.

## Temporary accounts and passphrases

Quick Connect with temporary credentials, and the SSH/SFTP retry actions, open a
dedicated protected document. Its preload exposes only context, ciphertext submit,
cancel and the platform capture-protection capability. The document has its own
Chromium partition, no ordinary application bridge, no Node integration and no
network access. It accepts a password account, a private key with an optional
certificate, or only a replacement passphrase for the selected saved key.

The document consumes its input buffers before asynchronous HPKE encryption and
clears its DOM on submission, mode change, cancellation and page loss. Main sees
only the envelope. Its independent cryptographic purpose binds the workspace,
target, session, request, protocol, host/port, authorization epoch, exact route and
endpoint, verified fingerprint, authenticated resolution revision, entry mode
and terminal/file options.

Go re-resolves and compares the complete snapshot under its owner lock before
wrapping that opaque envelope. Account mode borrows no stored account. Passphrase
mode borrows only the selected local key and certificate; it never borrows the
stored password or passphrase. An explicitly empty passphrase is an override.
Separate native manual-account and manual-passphrase operations reject saved
credential frames and mismatched entry modes. Only the native child decrypts and
combines the inner account with the authenticated options or selected key.

The native recipient consumes one ephemeral key and wipes its decrypted frames
after dialing. File-only mode cannot open a shell, terminal or auto-sudo path.
As with other protected documents, capture exclusion is available on Windows and
macOS; Linux displays the limitation while retaining isolation and encryption.

## Verification and remaining scope

Tests exercise the actual App factories, registered main handlers, native
admission and cleanup, standalone SFTP and shared file tabs. Chromium tests cover
the manual document's account/key/certificate modes, empty passphrase, input
consumption, errors, cancellation and late results. Go interoperability tests
independently verify its HPKE encoding and substituted contexts. Real local
SSH/SFTP servers cover saved and temporary accounts, direct and VPN routes,
temporary first-use trust and target lifetime through the last file tab.

Shared unsaved targets require audited PostgreSQL admission and remain pending;
the local registry and manual SSH authorization API reject shared use. Later
security profiles, provider-specific credential adapters and the broader #495
roadmap remain tracked in [the implementation status](vault-roadmap.md). These
tests do not establish interoperability with a user's remote host or VPN provider.
