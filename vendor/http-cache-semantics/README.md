# Local http-cache-semantics security backport

Based on the npm `http-cache-semantics@4.2.0` runtime file, with the original
BSD-2-Clause license. The local package name identifies this as a Wormhole fork,
not an upstream release.

Backports the runtime patch from
[kornelski/http-cache-semantics#58](https://github.com/kornelski/http-cache-semantics/pull/58)
at commit `14a8c2ad51740dc39bf3e8f1a11c845a5003f217` for
[CVE-2026-93748](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).
Cache reuse checks enforce response restrictions before considering `max-stale`
or stale-while-revalidate. Ordinary expiration and explicit public/immutable
cookie opt-ins retain their existing behavior.

Local hardening applies the same restrictions to stale-if-error and direct
stale-while-revalidate checks, verifies URL/method/host/Vary before error fallback,
and honors shared `s-maxage` revalidation requirements without changing fresh
response lifetimes. Cache directives are normalized case-insensitively, including
previously serialized policies; empty or duplicate directive values cannot clear
reuse prohibitions. Regression tests include an actual `cacheable-request` flow
against a local HTTP server returning a 500 after caching a user cookie.

The root npm override replaces all transitive installations with this package.
Remove the override and this directory once a reviewed upstream release includes
the fix. Do not replace it with unpatched `4.2.0`.

Regression and consumer integration tests are in `tests/dependency-security.test.mjs`.
Coverage uses Node's native test/V8 tooling. Unchanged upstream runtime code is
excluded from the changed-code coverage requirement; the backported executable
lines must have at least 80% coverage.

Validation: all 34 security regression tests pass. Node's native LCOV report
(`node --experimental-test-coverage --test-coverage-include=vendor/**/*.js
--test-reporter=lcov --test tests/dependency-security.test.mjs`) covers all
32 executable lines added by this backport (100%), compared with the original
npm runtime sources; blank lines, comments, and standalone delimiters are excluded.
