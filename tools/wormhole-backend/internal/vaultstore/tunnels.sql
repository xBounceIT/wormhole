CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL,
    RowVersion INTEGER NOT NULL CHECK (RowVersion >= 1),
    ConfigurationVersion INTEGER NOT NULL CHECK (ConfigurationVersion >= 1),
    Deleted INTEGER NOT NULL CHECK (Deleted IN (0,1)),
    Seal BLOB NOT NULL,
    EncryptedMetadata BLOB NULL,
    MetadataKeyId TEXT NULL,
    NameBlindIndex BLOB NULL
);
CREATE INDEX IX_TunnelConfigs_Active ON TunnelConfigs(Deleted, Id);
CREATE UNIQUE INDEX UX_TunnelConfigs_Name ON TunnelConfigs(Name) WHERE Deleted=0;
