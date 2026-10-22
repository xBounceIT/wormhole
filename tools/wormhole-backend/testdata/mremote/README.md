# mRemoteNG compatibility fixtures

All passwords here are public, synthetic test data. Every node password decrypts
to `demo-secret`. The test suite reads the checked-in XML without generating it
through Wormhole's encryption helper.

- `default-key.xml`: exact minimal fixture from
  [issue #462](https://github.com/xBounceIT/wormhole/issues/462), produced with the
  BouncyCastle.Crypto 1.8.1 library shipped by mRemoteNG 1.76.20. Master password:
  `mR3m`; verifier: `ThisIsNotProtected`.
- `custom-ascii.xml`: master password `Password1`, verifier `ThisIsProtected`.
- `custom-latin1.xml`: master password `Pässwörd1`, verifier `ThisIsProtected`.

The custom-password vectors were generated with BouncyCastle 1.8.1 from the
[NuGet package](https://www.nuget.org/packages/BouncyCastle/1.8.1), using
`Pkcs5PasswordToBytes`, PBKDF2-HMAC-SHA1 (1000 iterations, 256-bit key), AES-GCM
(128-bit nonce and tag), and the 128-bit salt as associated data. The payload is
`salt || nonce || ciphertext || tag` in Base64.

To reproduce the custom vectors, extract that package and run:

```powershell
./Generate-Fixtures.ps1 -BouncyCastlePath /path/to/lib/BouncyCastle.Crypto.dll
```

Fixed salts and nonces make these public vectors reproducible; they must never
be used for real credentials. BouncyCastle is only needed to regenerate fixtures,
not to run the Go tests.

Coverage is measured on the Go importer with `go test -coverprofile`. The offline
PowerShell fixture generator is excluded from Go coverage: it is test-data
tooling, never shipped or invoked by the app. Its output is exercised by the
golden import tests, and regeneration was verified against BouncyCastle 1.8.1.
