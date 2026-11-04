# Local deepmerge security backport

Based on the npm `deepmerge@4.3.1` CommonJS runtime and TypeScript declarations,
with the original MIT license. The package name identifies this as a Wormhole
fork rather than an upstream release.

Fixes [CVE-2026-93753](https://github.com/advisories/GHSA-gcqx-w48m-w2h4)
by rejecting `__proto__` before reading or copying keys in both merge loops,
as proposed in [TehShrike/deepmerge#274](https://github.com/TehShrike/deepmerge/pull/274).
This covers null-prototype targets, null/primitive placeholders, and own
`__proto__` keys in either input, including recursive merges and array clones.
Other keys and the upstream merge options retain their existing behavior.

The root npm override replaces every transitive installation, including the
`shadcn` and `@shadcn/registry` consumers. Remove the override and this directory
once a reviewed upstream release includes a fix. Do not restore unpatched 4.3.1.

Regression and consumer resolution tests are in `tests/dependency-security.test.mjs`.
Coverage uses the project's native Node test/V8 tooling, including this vendor
directory explicitly. Unchanged upstream code and TypeScript declarations are
excluded from changed-code coverage; all executable security patch lines must
meet the 80% threshold.

Validation: all 56 security tests pass. The complete vendored runtime has 100%
line and function coverage and 96.49% branch coverage, measured with:

```sh
node --experimental-test-coverage --test-coverage-include=vendor/deepmerge/index.js \
  --test-coverage-lines=80 --test-coverage-branches=80 --test-coverage-functions=80 \
  --test tests/dependency-security.test.mjs
```
