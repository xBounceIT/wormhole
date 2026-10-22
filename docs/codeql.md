# CodeQL scanning

The advanced workflow in `.github/workflows/codeql.yml` retains scanning for
Actions, C/C++, C#, JavaScript/TypeScript, and Go. Go uses manual builds of every
module under `tools/` for Linux, Windows, and macOS. The Windows-only credential
reader is built for Windows only. `go build -a` prevents the Go build cache from
hiding source files from CodeQL.

The default setup runs on Linux and cannot process the Windows-only credential
reader. It reports **Go files were found but not processed** even when the Actions
run succeeds. Custom build steps require advanced setup.

## Activation

1. Merge this workflow into `main`, then switch CodeQL from default to advanced
   setup under **Settings > Advanced Security > CodeQL analysis**. The workflow is
   already provided; keep all five language entries. GitHub rejects uploads from
   an advanced workflow while default setup is enabled.
2. Open **Actions > CodeQL** and, if disabled, select **Enable workflow** before
   dispatching it on `main`. Default setup can disable an advanced workflow;
   switching modes alone does not guarantee that the workflow is enabled.
3. Verify successful uploads for all five languages. Check the Go diagnostics and
   extracted-file coverage on the code scanning tool status page, in addition to
   the Actions conclusion. Confirm that the Windows credential reader is scanned.
4. If the tool status page still lists an inactive default-setup configuration,
   compare its analysis origin with the new workflow. Only after verifying the
   replacement scans, remove that stale configuration from `main` using GitHub's
   configuration controls. Do not dismiss its alerts as a way to clear the banner.

See GitHub's [setup troubleshooting](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/results-different-than-expected)
for workflow enablement and stale configuration handling.

## Scope

Go analysis uses the portable, non-CGO builds for `amd64`, including platform
adapters selected by `GOOS`. The macOS Keychain CGO implementation and the optional
OpenVPN3 CGO binding require native SDKs and are not part of these Go builds.
They were also excluded from the previous Linux default Go scan. C/C++ scanning
is retained separately. Application source code and runtime behavior are unchanged.

The regression tests exercise module discovery, platform selection, build command
execution, failure propagation, and workflow configuration. CodeQL's hosted
extraction and upload must be verified after activation; local unit coverage does
not measure the GitHub Actions service or YAML configuration.
