# Temporary VNC password handoff

This is the temporary-password flow for vault VNC connections in issue #495.
After a password-required failure, “Enter password securely” opens a separate
sandboxed, main-owned document. Local unsaved Quick Connect also uses this document
when a temporary password is selected. The ordinary app requests the mode using
public connection metadata and `manualPassword: true`; it cannot supply a password,
recipient or bundle. Saved-node requests continue to contain only their identifiers.

The protocol child announces its ephemeral X25519 public key. Direct metadata
comes from `vnc-plan`; routed metadata comes from the native tunnel lease. The
password document seals its password to that key. Main relays only ciphertext to
`vnc-manual-bundle` or `vnc-manual-route-bundle`. The vault re-resolves the node,
compares the destination and route, and wraps the opaque envelope to the same
recipient. It never fetches a saved password for these operations.

`--operation vnc-manual-sealed` accepts one opening. It opens the owner's outer
authorization and then the inner password before disposing its recipient key.
Normal and manual-only recipients reject each other's payload formats. There is
no saved-password fallback.

## Local Quick Connect and session ownership

The public command selects either a saved node or an exact VNC target containing
host, port and selected credential/tunnel IDs. Main registers an unsaved target
in the unlocked Go owner's bounded ephemeral registry, bound to workspace,
session and main authorization epoch. Registration borrows no secret and creates
no SQL node, row version or persisted metadata seal. Every plan/bundle uses the
scoped resolver and rechecks current selected account and tunnel metadata. Shared
Quick Connect remains refused until its separate audited admission exists.

Main reserves the window/session before authorization or registration starts.
Disconnect, reload, destruction and global shutdown cancel and join pending work,
including a late native target receipt. The controller owns the target lease
until native close is confirmed. It then releases the original Go admission;
uncertain release requires confirmed original-owner exit, or retains a retryable
cleanup barrier. The owning registry is not replaced by a new workspace during
cleanup. Every retry admits a fresh target and recipient. Catalog creation and
duplicated protected desktop tabs use canonical session UUIDs.

Input authorization also captures the main admission generation. A queued key or
pointer operation cannot reach a same-window replacement, and its cleanup cannot
retire that replacement. Equivalent public target metadata does not reconnect a
surface merely because its object identity changed.

Only the public temporary-password intent is retained in app session state. It
survives disconnect, surface remount and tab duplication. The password remains in
the isolated document and Go recipient; every attempt requires fresh entry. A
new session cannot inherit another surface's private mode. Selecting temporary
entry for Quick Connect removes the saved primary reference for that attempt.
There is no implicit fallback to a saved password after failure or cancellation.
An absent password stays absent for an initial connection without a selected
credential, allowing VNC servers without authentication. Explicit manual entry,
including an empty password, uses the protected document and its presence flag.

Native integration tests cover saved and unsaved targets, both account modes and
direct/VPN routes. They use a real Go vault/recipient and independent RFB test
server to authenticate, stream a frame and accept pointer/key input. Additional
unsaved variants distinguish absent passwords from explicitly empty manual entry
on both direct and VPN routes. Unsaved cases
retain zero catalog nodes before/after retirement and reject the retired target.
Actual App submit/catalog/duplicate/SessionSurface tests reach the public parser;
actual Chromium tests verify mode persistence and absence of ordinary vault
password fields. These checks do not establish interoperability with a user's
remote server, production VPN provider or native macOS/Linux runtime.

## Inner HPKE context

Suite: X25519/HKDF-SHA256/AES-256-GCM (the existing native suite identifier).
Info starts with UTF-8 `wormhole/v1/vnc-manual-password`, followed by fourteen
UTF-8 fields, each prefixed by its unsigned 32-bit big-endian **byte** length:

1. workspaceId
2. nodeId
3. sessionId
4. requestId
5. protocol (`vnc`)
6. host (original authenticated spelling)
7. port (canonical decimal)
8. tunnelConfigId (empty for direct)
9. epoch (canonical decimal, positive JavaScript-safe integer)
10. fileId (empty for direct)
11. tunnel kind (canonical decimal; empty for direct)
12. rowVersion (canonical decimal string; empty for direct)
13. configurationVersion (canonical decimal string; empty for direct)
14. endpoint (`127.0.0.1:<canonical port>`; empty for direct)

External clients, noncanonical/nil UUIDs, control/whitespace hosts, invalid
ports/epochs and mismatched route/base bindings are rejected. Purpose, target,
request, session, epoch, recipient and route substitutions cannot authenticate.
The field-order/UTF-8 test pins this interop context.

Inner plaintext uses the existing version 1 VNC frame: byte `1`, explicit presence
byte `1`, unsigned 32-bit big-endian length, then at most 16384 password bytes.
Empty is explicit. Inner ciphertext is 22..16406 bytes, with a separate 32-byte
encapsulation. The native decoder borrows the plaintext frame; the session consumes
the password once and wipes its bytes. Teardown joins the worker before clearing
the entire frame.

## Owner authorization

Outer HPKE uses the existing direct/routed protocol binding. Its plaintext is a
separate version 2 authorization containing ciphertext only:

| Bytes | Meaning |
| --- | --- |
| 0 | version `2` |
| 1..32 | inner encapsulation, 32 bytes |
| 33..36 | inner ciphertext length, unsigned 32-bit big-endian |
| 37..end | inner ciphertext |

The exact length is 59..16443 bytes. Version 2 fixes the envelope format/suite.
Trailing data, truncation and inconsistent lengths are rejected. Decoding borrows
the outer frame. Both authorizations must succeed before dialing. Subsequent host
normalization preserves the authenticated explicit port.

Saved recipients retain their 30-second opening deadline. Manual-only recipients
allow at most five minutes for the isolated document, followed by the existing
bounded network handshake. EOF, lock and malformed input retire the child/key.
The main relay allows a bounded input deadline and cancels the document on owner,
route or authorization-epoch loss. A fresh partition, restricted preload, disabled
Node integration/DevTools, permission and download denial, strict CSP and existing
content-protection policy isolate the document. Linux displays its capture
protection limitation. The password lives only in the document's input and
short-lived encryption buffers; the input is cleared before awaiting encryption,
and caller/frame bytes are cleared on completion or cancellation. Only ciphertext
crosses its preload. The document is destroyed before the outer authorization is
requested; an unconfirmed destruction prevents a successful lock acknowledgement.

Tests cover exact context/size validation, explicit empty passwords, late crypto
and native replies, navigation/crashes, tunnel loss and unconfirmed teardown. A
sandboxed Chromium document with its actual preload encrypts a synthetic password
that Go independently opens. End-to-end relay fixtures use a real SQLite vault,
a different saved password, native direct/VPN recipients and an independent RFB
server to verify password selection, frames and controls. These fixtures do not
establish interoperability with every VNC server or native macOS/Linux runtime.

On Windows, native shutdown accepts either the normal process exit state or an
OS “no such process” result for the main-owned positive PID. This handles an
observed delay between process disappearance and Node's exit notification. A
present/reused PID, unavailable PID, permission failure or any other query error
keeps termination unconfirmed. Deadlines and retirement reservations remain
unchanged. Native-owner and protocol shutdown share this proof; tests also wait
for the later Node handle closure before deleting fixture executables.
