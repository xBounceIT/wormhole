# Migration Rust toolchain (Windows agents)

Rust/cargo are often **not** on the shell `PATH` in Cursor agent sessions even when already installed for the user. Prefer the existing per-user install; do **not** run `winget install Rustlang.Rustup` or download rustup unless binaries are missing.

## Location

| Tool | Path |
|------|------|
| Cargo home / binaries | `%USERPROFILE%\.cargo\bin` |
| rustup home | `%USERPROFILE%\.rustup` |
| rustup | `C:\Users\dange\.cargo\bin\rustup.exe` |
| cargo | `C:\Users\dange\.cargo\bin\cargo.exe` |
| rustc | `C:\Users\dange\.cargo\bin\rustc.exe` |

## Versions (discovered 2026-07-31)

| Component | Version |
|-----------|---------|
| rustup | 1.29.0 (28d1352db 2026-03-05) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| Default toolchain | `stable-x86_64-pc-windows-msvc` |

Installed targets on that toolchain:

- `x86_64-pc-windows-msvc`
- `aarch64-pc-windows-msvc`

## PATH for agents (PowerShell)

Prefix the cargo bin directory for the current session before `cargo` / `rustc` / `rustup`:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo --version
rustc --version
```

Or invoke by full path:

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" --version
& "$env:USERPROFILE\.cargo\bin\rustc.exe" --version
```

## Notes

- Default host: `x86_64-pc-windows-msvc`
- No C# app changes are required for this toolchain doc.
- If `%USERPROFILE%\.cargo\bin\cargo.exe` is absent, install rustup for the current user only after confirming with the user; otherwise use the existing install above.
