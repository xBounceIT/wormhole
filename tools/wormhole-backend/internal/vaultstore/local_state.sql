CREATE TABLE LocalState (
    Id TEXT PRIMARY KEY NOT NULL,
    Kind TEXT NOT NULL,
    ScopeId TEXT NOT NULL,
    Size INTEGER NOT NULL CHECK (Size >= 0 AND Size <= 67108864),
    RowVersion INTEGER NOT NULL CHECK (RowVersion >= 1),
    Deleted INTEGER NOT NULL CHECK (Deleted IN (0,1)),
    SecretManifest BLOB NOT NULL,
    Seal BLOB NOT NULL,
    UNIQUE (Kind, ScopeId)
);
CREATE TABLE SecretValuesV6 (
    OwnerKind TEXT NOT NULL CHECK (OwnerKind IN ('credential','node','tunnel','slot-value','local-state')),
    OwnerId TEXT NOT NULL,
    Field TEXT NOT NULL,
    DekId TEXT NOT NULL,
    DekVersion INTEGER NOT NULL,
    Envelope BLOB NOT NULL,
    RowVersion INTEGER NOT NULL DEFAULT 1 CHECK (RowVersion >= 1),
    PRIMARY KEY (OwnerKind, OwnerId, Field),
    FOREIGN KEY (DekId, DekVersion) REFERENCES Keys(KeyId, KeyVersion)
);
INSERT INTO SecretValuesV6 SELECT OwnerKind,OwnerId,Field,DekId,DekVersion,Envelope,RowVersion FROM SecretValues;
DROP TABLE SecretValues;
ALTER TABLE SecretValuesV6 RENAME TO SecretValues;
