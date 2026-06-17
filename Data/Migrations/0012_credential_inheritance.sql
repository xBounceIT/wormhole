-- 0012_credential_inheritance: explicit tri-state credential binding.
-- NULL preserves the legacy meaning:
--   CredentialId IS NOT NULL -> saved credential
--   CredentialId IS NULL     -> inherit from ancestor
-- Non-null values use CredentialBindingMode:
--   0 = inherit, 1 = no credential, 2 = saved credential.

ALTER TABLE Nodes ADD COLUMN CredentialMode INTEGER NULL;
