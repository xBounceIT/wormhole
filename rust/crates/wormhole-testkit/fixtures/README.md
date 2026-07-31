# Wormhole test fixtures

| File | Contents |
|------|----------|
| `empty-schema.db` | SQLite DB after all `Data/Migrations/*.sql` applied; `__migration_history` filled; **no** connection/credential/tunnel rows and **no** secrets |
| `mremoteng-sample.xml` | Synthetic mRemoteNG ConfVersion 2.7 export (SSH/RDP/VNC + skipped HTTPS/Serial); documentation hosts only; `cipher-ssh` uses a known AES-GCM test vector (`lab-secret` / `import-pw`); `bad-cipher-ssh` is fail-closed placeholder |

Regenerate empty schema (from `rust/`):

```powershell
cargo test -p wormhole-storage --test generate_empty_schema_fixture -- --ignored --nocapture
```

Do not commit real `%LOCALAPPDATA%\Wormhole\wormhole.db` copies or real mRemoteNG password vaults.
