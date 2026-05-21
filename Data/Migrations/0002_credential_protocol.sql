-- 0002_credential_protocol: store the protocol scope (Ssh/Rdp) for each credential.

ALTER TABLE CredentialProfiles ADD COLUMN Protocol INTEGER NOT NULL DEFAULT 0;

UPDATE CredentialProfiles
SET Protocol = 1
WHERE Domain IS NOT NULL AND TRIM(Domain) <> '';
