-- 0005_aad_credentials_use_external_client: backfill RdpUseExternalClient=1 on existing
-- RDP connection nodes whose linked credential matches the Azure-AD heuristic. Without
-- this, profiles created before the editor learnt to auto-flag AAD credentials still
-- crash the embedded mstscax host with SEH 0xC06D007F on first connect attempt. Runs
-- once at startup via MigrationRunner.
--
-- Integer values are the enum ordinals from Models/NodeKind.cs (Connection=1) and
-- Models/ProtocolType.cs (Rdp=1). Username uses an escaped backslash because '\' has
-- no special meaning in SQLite LIKE; the literal pattern 'azuread\%' matches.
-- Only NULL/0 rows are touched so that profiles where the user has already set the
-- flag explicitly (in either direction) keep their choice.

UPDATE Nodes
SET RdpUseExternalClient = 1
WHERE Kind = 1
  AND Protocol = 1
  AND (RdpUseExternalClient IS NULL OR RdpUseExternalClient = 0)
  AND CredentialId IN (
      SELECT Id FROM CredentialProfiles
      WHERE LOWER(IFNULL(Domain, '')) = 'azuread'
         OR LOWER(IFNULL(Username, '')) LIKE 'azuread\%'
  );
