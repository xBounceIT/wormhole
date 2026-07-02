-- 0014_bitwarden_credentials: optional external password references through Bitwarden CLI.

ALTER TABLE CredentialProfiles ADD COLUMN SecretProvider INTEGER NOT NULL DEFAULT 0;
ALTER TABLE CredentialProfiles ADD COLUMN BitwardenItemId TEXT NULL;
ALTER TABLE CredentialProfiles ADD COLUMN BitwardenItemName TEXT NULL;
ALTER TABLE CredentialProfiles ADD COLUMN BitwardenFieldPath TEXT NOT NULL DEFAULT 'login.password';
