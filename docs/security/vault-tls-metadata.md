# Shared TLS metadata retrieval

Schema migration 9 adds a bounded signed TLS bundle and its sequence to the
private workspace metadata row. It accepts only schema 8 for the exact workspace
and role tag. An unprovisioned workspace has sequence zero and a null bundle;
retrieval then fails with the fixed `WH011` error.

The `tls_trust_bundle(bytea)` SQL API requires a current audited device capability,
uses a fixed search path, and holds a shared metadata-row lock while reading the
sequence and document together. PUBLIC has no execute grant. Device roles cannot
read or update the underlying table. Provisioning still writes as database owner;
this migration does not provide an administrative publication API.

Native `Session.TLSTrustBundle` uses the existing serialized session control and
query lease. It bounds the document to 1 MiB, rejects noncanonical documents and
workspace/sequence mismatches, and retires the connection on malformed responses.
Temporary capability encodings and result buffers are wiped.

The returned document is explicitly **unverified**. A caller must verify the
organisation signature against an independently authenticated key and enforce the
durable sequence/digest floor before accepting it. An authenticated database
connection does not replace this check. Initial TLS bootstrap cannot depend on
this post-authentication API.

Real PostgreSQL tests cover migration identity/replay rejection, missing metadata,
valid signed retrieval, storage bounds, table and PUBLIC privileges, forged
capabilities, and connection retirement after a malformed server document. Unit
tests cover context/session guards, malformed rows and signature trust separation.
SQL behavior is measured by these integration tests; the Go coverage tool does not
instrument PL/pgSQL.

For transports enrolled with a signed bundle, the native admission controller
checks current server metadata before publishing admission and before account-key
use (unlock or password change). `RefreshTLS` provides the same check for an
already admitted owner. An unchanged authenticated bundle preserves the owner;
a newer bundle is committed to the protected floor and cache before returning
`shared_workspace_tls_reconnect_required` and closing the owner, including its
query and notification connections. Errors during verification or persistence
also retire the owner. A fresh admission loads the new bundle from the cache.
Legacy transports are not implicitly enrolled using a server-supplied trust key.

Password-change recovery performs the check against the journal's observed trust
and commits newer metadata to that journal and cache before stopping for a fresh
connection. It does not finalize the root transition over an obsolete transport.
Cancellation on controller close interrupts an in-flight refresh; normal operation
gating prevents account use from overtaking the refresh.

After admission, managed TLS owners run a native monitor. It polls every 30
seconds even when notifications are enabled, so a missing hint cannot suppress
the next check. Deployments with at most 300 devices and without a transaction
pooler subscribe on the dedicated notification connection before the initial
metadata check. Other deployments use polling alone.

Notification IDs carry no authority. The monitor queues one hint, applies
backpressure to the reader and refreshes at most once per one-second clock tick.
The polling-only clock wakes every 30 seconds. A failed notification stream
retires the controller. Closing the controller cancels pending reads and stops
the monitor clock. Any operation already holding the controller gate can delay
a refresh until it releases the gate; the operation's existing timeout remains
in force.

Administrative publication UI/API and the general `get_changes_since` workspace
change feed remain integration work. The TLS monitor does not implement tree,
permission or secret synchronization.
