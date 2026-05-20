-- 0001_initial: tree of connection nodes + named credential profiles.

CREATE TABLE Nodes (
    Id                       TEXT     PRIMARY KEY NOT NULL,
    ParentId                 TEXT     NULL REFERENCES Nodes(Id) ON DELETE CASCADE,
    Name                     TEXT     NOT NULL,
    Kind                     INTEGER  NOT NULL,
    SortOrder                INTEGER  NOT NULL DEFAULT 0,
    Protocol                 INTEGER  NULL,
    Host                     TEXT     NULL,
    Port                     INTEGER  NULL,
    Username                 TEXT     NULL,
    CredentialId             TEXT     NULL,
    RdpDomain                TEXT     NULL,
    RdpScreenSize            TEXT     NULL,
    RdpFullScreen            INTEGER  NULL,
    SshKeyFileName           TEXT     NULL,
    SshKnownHostFingerprint  TEXT     NULL,
    CreatedAt                TEXT     NOT NULL,
    UpdatedAt                TEXT     NOT NULL
);

CREATE INDEX IX_Nodes_ParentId ON Nodes(ParentId);

CREATE TABLE CredentialProfiles (
    Id                  TEXT     PRIMARY KEY NOT NULL,
    Name                TEXT     NOT NULL,
    Username            TEXT     NULL,
    Domain              TEXT     NULL,
    Kind                INTEGER  NOT NULL,
    PrivateKeyFileName  TEXT     NULL,
    CreatedAt           TEXT     NOT NULL
);

CREATE UNIQUE INDEX UX_CredentialProfiles_Name ON CredentialProfiles(Name);
