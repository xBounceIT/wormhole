CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    OwnerUserId TEXT NULL,
    Name TEXT NOT NULL,
    Protocol TEXT NOT NULL,
    Kind TEXT NOT NULL,
    Username TEXT NOT NULL,
    Domain TEXT NOT NULL,
    SecretProvider TEXT NOT NULL,
    BitwardenItemId TEXT NOT NULL,
    BitwardenItemName TEXT NOT NULL,
    BitwardenFieldPath TEXT NOT NULL,
    PrivateKeyFileName TEXT NOT NULL,
    CertificateFileName TEXT NOT NULL,
    RowVersion INTEGER NOT NULL CHECK (RowVersion >= 1),
    Deleted INTEGER NOT NULL CHECK (Deleted IN (0,1)),
    SecretManifest BLOB NOT NULL,
    Seal BLOB NOT NULL,
    EncryptedMetadata BLOB NULL,
    MetadataKeyId TEXT NULL,
    NameBlindIndex BLOB NULL
);
CREATE INDEX IX_CredentialProfiles_Active ON CredentialProfiles(Deleted, Id);
CREATE UNIQUE INDEX UX_CredentialProfiles_OwnerName ON CredentialProfiles(COALESCE(OwnerUserId,''), Name) WHERE Deleted=0;
