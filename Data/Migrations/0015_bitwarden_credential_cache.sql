-- 0015_bitwarden_credential_cache: metadata-only cache for Bitwarden login items.

CREATE TABLE IF NOT EXISTS BitwardenCredentialCache (
    ItemId             TEXT PRIMARY KEY NOT NULL,
    SshCredentialId    TEXT NOT NULL,
    RdpCredentialId    TEXT NOT NULL,
    VncCredentialId    TEXT NOT NULL,
    Name               TEXT NOT NULL,
    Username           TEXT NULL,
    RevisionDate       TEXT NULL,
    LastSeenSyncUtc    TEXT NOT NULL,
    UpdatedAtUtc       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS IX_BitwardenCredentialCache_Name
    ON BitwardenCredentialCache(Name);
