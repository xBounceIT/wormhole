# Public TLS bundle cache

The native controller saves a verified TLS bundle before advancing its protected
sequence/digest floor. Cache entries are canonical signed public metadata, not
private keys or account credentials. They live beside the device trust file in
`<trust-file>.tls/<sha256-of-canonical-bundle>.json`.

Content-addressed names avoid a concurrent stale writer replacing the bundle
referenced by a newer committed floor. Publication uses the existing temporary
file, file-sync, atomic replacement and directory-sync writer, followed by a
parent-directory sync. A failed attempt may retry the same immutable content once;
failure still prevents floor publication and network access. Readback alone is
not used as proof that a failed sync became durable.

A separate cache lock serializes writes, entry counting, retention and protected
reference publication. It remains held until the floor/journal commit finishes;
releasing it after only the cache write would permit cleanup to delete a snapshot
whose reference is about to commit. Cache operations acquire the cache lock before
the trust-file lock, consistently. Paths must be native
absolute paths; the cache directory must be a directory rather than a symlink,
and existing destinations must be regular files. Reads are bounded by the bundle
size limit and require both the exact protected digest and normal bundle
signature/identity/sequence verification. Malformed, missing or replaced content
never falls back to raw CA PEM or unverified transport.

On a Verified TLS restart without a caller-supplied bundle, the controller loads
the exact snapshot named by the authenticated protected state. Password recovery
uses the pending journal's observed state, so a newer observed TLS floor selects
its own cached snapshot before reconciliation. A caller supplying an independently
verified matching bundle can repair a missing/corrupt cached copy before use.

Before an ordinary publication, retention authenticates the current protected
record under its file lock and requires it to equal the caller's expected state.
It keeps the current and incoming digests and removes other direct regular files
only when their canonical names, content hashes and organisation/workspace
signatures all verify. Unrelated names, foreign bundles, corrupt data and
directories are not deleted. Directory deletion metadata is synchronized before
publication continues. Ordinary rotations retain at most the previous/current
snapshots; a later confirmation can remove the previous one.

No pruning runs during a pending password transition, since an interrupted
destination may use a different root key. After recovery completes, ordinary
publication can clean those copies. The cache allows 64 entries, each bounded by
the 1 MiB bundle limit; an existing snapshot can be rewritten at the limit, while
adding an entry still fails closed with `shared_workspace_tls_cache_full` if
protected recovery copies or unowned entries occupy the capacity. Retention reads
only a bounded batch and never recursively removes directories.

Tests cover integrity/reload, snapshots coexisting across sequence updates,
bounded entry counts, locks, invalid paths/nonregular entries, valid-copy repair,
restart, pending-journal recovery and missing-cache refusal before network. Cache,
protected-floor and journal-sync fault paths are exercised separately. Tests also
cover rotation retention, stale/wrong-root cleanup attempts, pending-transition
preservation, foreign/unowned content and the lock spanning protected publication.
