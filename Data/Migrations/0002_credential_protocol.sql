-- 0002_credential_protocol: store the protocol scope (Ssh/Rdp) for each credential.
-- Protocol values mirror Models/ProtocolType.cs: 0 = Ssh, 1 = Rdp (2 = Sftp, unused for credentials).

ALTER TABLE CredentialProfiles ADD COLUMN Protocol INTEGER NOT NULL DEFAULT 0;

-- Backfill existing rows with a non-empty Domain as Rdp; everything else stays at the default (Ssh).
UPDATE CredentialProfiles
SET Protocol = 1
WHERE Domain IS NOT NULL AND TRIM(Domain) <> '';
