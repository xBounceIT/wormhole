CREATE TABLE WorkspaceMeta (
    Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1),
    WorkspaceId TEXT NOT NULL,
    FileId TEXT NOT NULL,
    SchemaVersion INTEGER NOT NULL CHECK (SchemaVersion >= 1),
    RootKeyId TEXT NOT NULL,
    RootKeyVersion INTEGER NOT NULL CHECK (RootKeyVersion >= 1),
    ChangeSeq INTEGER NOT NULL DEFAULT 0 CHECK (ChangeSeq >= 0),
    ResolverVersion INTEGER NOT NULL DEFAULT 1,
    SignedProfile BLOB NULL
);
CREATE TABLE Keys (
    KeyId TEXT NOT NULL,
    KeyVersion INTEGER NOT NULL CHECK (KeyVersion >= 1),
    Kind TEXT NOT NULL CHECK (Kind IN ('user-enc','user-sign','device','group','org-enc','org-sign','recovery','recovery-share','boundary-view','boundary-secret','boundary-write','dek','vault')),
    OwnerId TEXT NULL,
    Status TEXT NOT NULL DEFAULT 'active' CHECK (Status IN ('pending','active','rotating','retired')),
    Suite INTEGER NOT NULL,
    PublicKey BLOB NULL,
    CertSignerKeyId TEXT NULL,
    CertSignerKeyVersion INTEGER NULL,
    CertSignature BLOB NULL,
    CreatedAt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    RowVersion INTEGER NOT NULL DEFAULT 1 CHECK (RowVersion >= 1),
    PRIMARY KEY (KeyId, KeyVersion),
    FOREIGN KEY (CertSignerKeyId, CertSignerKeyVersion) REFERENCES Keys(KeyId, KeyVersion)
);
CREATE UNIQUE INDEX UX_Keys_OneActive ON Keys (Kind, COALESCE(OwnerId, '00000000-0000-0000-0000-000000000000')) WHERE Status = 'active';
CREATE TABLE KeyCopies (
    KeyId TEXT NOT NULL,
    KeyVersion INTEGER NOT NULL,
    HolderKeyId TEXT NOT NULL,
    HolderKeyVersion INTEGER NOT NULL,
    Suite INTEGER NOT NULL,
    Enc BLOB NOT NULL,
    Ciphertext BLOB NOT NULL,
    IssuerKeyId TEXT NOT NULL,
    IssuerKeyVersion INTEGER NOT NULL,
    Signature BLOB NOT NULL,
    CreatedAt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (KeyId, KeyVersion, HolderKeyId, HolderKeyVersion),
    FOREIGN KEY (KeyId, KeyVersion) REFERENCES Keys(KeyId, KeyVersion) ON DELETE CASCADE,
    FOREIGN KEY (HolderKeyId, HolderKeyVersion) REFERENCES Keys(KeyId, KeyVersion),
    FOREIGN KEY (IssuerKeyId, IssuerKeyVersion) REFERENCES Keys(KeyId, KeyVersion),
    CHECK (NOT (KeyId = HolderKeyId AND KeyVersion = HolderKeyVersion))
);
CREATE INDEX IX_KeyCopies_Holder ON KeyCopies (HolderKeyId, HolderKeyVersion);
CREATE TABLE SecretValues (
    OwnerKind TEXT NOT NULL CHECK (OwnerKind IN ('credential','node','tunnel','slot-value')),
    OwnerId TEXT NOT NULL,
    Field TEXT NOT NULL,
    DekId TEXT NOT NULL,
    DekVersion INTEGER NOT NULL,
    Envelope BLOB NOT NULL,
    RowVersion INTEGER NOT NULL DEFAULT 1 CHECK (RowVersion >= 1),
    PRIMARY KEY (OwnerKind, OwnerId, Field),
    FOREIGN KEY (DekId, DekVersion) REFERENCES Keys(KeyId, KeyVersion)
);
