# Argon2id working memory on macOS

This internal copy of Go's Argon2 implementation accepts a caller-owned slice of
one-KiB blocks. The macOS vault allocates those blocks in a private anonymous
mapping and wipes and unmaps them before returning the derived key. This also
runs inside the vault's existing derivation gate.

The block processing, architecture-specific implementations and BLAKE2b code
are copied from `golang.org/x/crypto` v0.58.0. The changes in `argon2.go`
expose the block type, accept the supplied storage and limit the entry point to
the vault's Argon2id parameters and 32-byte output. Reconcile these files when
updating the pinned dependency. The interoperability tests compare the result
with that version's `argon2.IDKey`. [Upstream source](https://github.com/golang/crypto/tree/v0.58.0/argon2) · [License](LICENSE)
