# Native SCRAM verifier generation

`sharedpg.NewSCRAMVerifier` generates a PostgreSQL SCRAM-SHA-256 verifier locally
from exactly 32 bytes of HKDF login material. The daily-login caller derives that
material with `vault.PurposeLogin` from the account master; enrollment uses its
separate invite-login derivation. This API is not a raw Wormhole password API.

`EncodeLoginSecret` produces the unpadded base64url ASCII secret supplied to the
native PostgreSQL connector. The same conversion happens inside verifier
generation, so the role verifier authenticates exactly that encoded secret. Its
ASCII alphabet avoids any SASLprep ambiguity. The caller must wipe returned
login bytes and verifier bytes and must never log either or place them in process
arguments. Input login material is borrowed and remains unchanged.

Generation uses a fresh 32-byte cryptographic random salt and PBKDF2-HMAC-SHA256
with 4096 iterations. It computes `Client Key`, its SHA-256 `StoredKey`, and
`Server Key`, then emits PostgreSQL's canonical representation:

```text
SCRAM-SHA-256$4096:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
```

The application password has already undergone Argon2id and any required ASK
mix before HKDF. The SCRAM iteration count does not replace that password KDF.
Temporary encoded login material, salted password and client/server key buffers
are wiped. Go cryptographic implementation internals are not claimed to be fully
zeroizable.

`ValidateSCRAMVerifier` accepts at most 256 bytes, the exact algorithm label,
canonical decimal costs from 4096 to 1000000, a 16–64-byte salt and exactly two
32-byte keys. Standard padded base64 must round-trip exactly; whitespace,
embedded newlines, ambiguous padding, alternate alphabets, additional fields,
weak costs and excessive costs are rejected with one fixed error. Validation
does not derive a password and therefore cannot establish knowledge of the
credential or authorization to replace it. The future server API must enforce
the same checks independently of a cooperative native client.

An independent Python `hashlib`/`hmac` vector pins conversion and derivation.
Real PostgreSQL tests bind the generated verifier as a query parameter to a
test-only role setter, confirm it is stored verbatim, authenticate with the
encoded derived secret, reject a wrong secret, and replace the verifier. Old
credentials then fail on new connections while the new credentials succeed.

Changing a role verifier does not terminate existing PostgreSQL sessions. The
eventual atomic password-change API must update all device verifiers and the
wrapped user keys together and separately retire or invalidate old admitted
sessions. No production role-management or password-change API is enabled by
these primitives.
