# Local braces security backport

Based on the npm `braces@3.0.3` runtime files, with the original MIT license.
The local package name identifies this as a Wormhole fork, not an upstream release.

Backports the runtime patch from [micromatch/braces#72](https://github.com/micromatch/braces/pull/72)
at commit `28d440b5dd449dbf1fe6f3506cf94ecca4d02660` for
[CVE-2026-93687](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm): parsing and
AST walkers cap nesting at 100 (including parentheses), honor stricter
`maxDepth` values, and reject cyclic expansion parent chains.

Local hardening also removes an upstream debug print from compilation of
caller-supplied closing AST nodes, so pattern contents never reach stdout.
Stringification preserves the containing AST node for `escapeInvalid`, and the
invalid-brace predicate counts commas and ranges independently so valid ranges
are not escaped.

The root npm override replaces all transitive `braces` installations with this
package. Remove the override and this directory once a reviewed upstream release
includes the fix. Do not replace it with unpatched `3.0.3`.

Regression and consumer integration tests are in `tests/dependency-security.test.mjs`.
Coverage uses Node's native test/V8 tooling. Unchanged upstream runtime code is
excluded from the changed-code coverage requirement; the backported executable
lines must have at least 80% coverage.

Validation: all 40 security regression tests pass. Node's native LCOV report
(`node --experimental-test-coverage --test-coverage-include=vendor/**/*.js
--test-reporter=lcov --test tests/dependency-security.test.mjs`) covers all
45 executable lines added by this backport (100%), compared with the original
npm runtime sources; blank lines, comments, and standalone delimiters are excluded.
