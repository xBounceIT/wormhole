# SSH keys and user certificates

Create an SSH private key credential in **Credentials**, or choose **Use an SSH
key or certificate…** in the connection editor. The shortcut creates a saved
credential and selects it for the connection or Quick Connect session.

The private key picker shows extension-less files such as `id_ed25519`. It accepts
OpenSSH, PKCS#1, SEC1 and PKCS#8 keys up to 1 MiB, including encrypted OpenSSH,
legacy encrypted PEM and PBES2-encrypted PKCS#8. A key passphrase is optional at
import: when it is omitted, connecting prompts for it without saving it.

An optional certificate must be a single OpenSSH user certificate line up to
16 KiB. Selecting a key suggests its sibling `<key>-cert.pub`, when present;
remove that suggestion or select another certificate as needed. Host certificates
and plain public key files are rejected. Its signature is verified against the
embedded CA key; the server determines which CAs and principals it trusts.
The editor shows the saved certificate's
key ID, principals and expiry. Use **Replace…** to renew just the certificate, or
**Remove** to return to plain key authentication. A failed connection with an
expired certificate offers **Replace certificate…** for the affected credential,
including when the credential was inherited from a folder.

SSH offers the certificate before the plain public key, so the same credential
also works with servers that accept only the raw key. Certificates must match the
key and be within their validity window, allowing 30 seconds of clock skew. When
an encrypted OpenSSH key is saved without a passphrase, its public half permits
the match check at import. Other encrypted PEM/PKCS#8 keys defer that check until
their passphrase is available. SFTP shares the authenticated SSH transport.

Private keys remain in the protected native key store. Selecting a file returns
only an opaque selection ID and display name to the renderer; key bytes and file
paths are resolved in the native flow. Passphrases use the existing one-shot
secret inputs and protected secret storage. The public certificate lives in the
credential's database row and is saved atomically with its metadata. Replacing
only a certificate does not rewrite the protected key file.

Encrypted backups carry the key and certificate. Restore checks newly imported
certificates and certificates belonging to repaired keys against the restored
key material when possible. Invalid or mismatched certificates are dropped in the
key's restore transaction, with a warning, while preserving the key. Matching
independently renewed certificates survive a backup merge.

PKCS#8 decryption uses an in-tree PBES2 decoder with PBKDF2 (HMAC SHA-1,
SHA-224/256/384/512) or scrypt and AES-CBC, AES-GCM or 3DES-CBC. Derived keys,
decrypted DER and passphrase buffers are cleared after use. KDF input is bounded:
PBKDF2 permits up to 10 million iterations; scrypt permits up to 256 MiB of memory
and a bounded work factor. Unsupported formats or excessive parameters produce
an import error. PuTTY PPK files currently receive a `puttygen` conversion hint;
agent, hardware-key and Bitwarden SSH-key item support remain separate features.

## Verification

Run `npm run test:credential-state` for the credential projection tests, native
IPC handler tests and mounted Chromium editor/connection tests. Run `go test ./...`
from `tools/wormhole-backend` for parsing, protected CRUD, migration, backup and
in-process CA-only SSH server tests, including plain-key fallback and RSA SHA-2.

Node's coverage runner measures the TypeScript state helpers. V8 coverage in the
native-handler and Chromium harnesses measures the changed process-entrypoint and
editor functions, which Node's module coverage cannot instrument directly. Go's
coverage profile measures new and modified executable statements; declarations,
types, generated JSX and documentation are outside that statement metric.
External SSH services and provider-specific CA configuration still require manual
interoperability checks.
