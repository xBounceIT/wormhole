-- 0009_drop_sftp_protocol: SFTP is no longer a standalone session protocol — it only exists
-- as file transfer over an SSH session. Reclassify any saved connection that was created as
-- SFTP (Protocol = 2, the old Models/ProtocolType.cs value) to SSH (0) so it still opens and
-- doesn't hit the "unknown protocol" path in SessionTabFactory. Credentials never used the
-- SFTP value, so CredentialProfiles needs no change. MigrationRunner wraps this in a transaction.

UPDATE Nodes
SET Protocol = 0
WHERE Protocol = 2;
