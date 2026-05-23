-- 0006_aad_node_fields_use_external_client: extend migration 0005's backfill to also cover
-- AAD signals on the node itself (RdpDomain / Username), not just the linked credential.
-- 0005 only matched profiles with a CredentialId pointing at an AAD CredentialProfile, but
-- the production crash case had CredentialId=NULL ("Prompt every time") with RdpDomain set
-- to 'AzureAD' — 0005 left those rows untouched, the embedded path was still chosen at
-- connect, and mstscax crashed the process. The runtime ShouldUseExternalClientAsync now
-- catches them via the heuristic, but persisting the flag here keeps the editor's checkbox
-- state consistent with the runtime decision (otherwise the box shows unchecked-and-disabled,
-- which is confusing UX).
--
-- WHERE clause restricts to nodes that:
--   * Are RDP connections (Kind=1, Protocol=1 — see Models/NodeKind.cs and Models/ProtocolType.cs)
--   * Don't already have the flag explicitly set (NULL or 0 — preserves any user override)
--   * Carry an AAD signal directly on the node row:
--     - LOWER(TRIM(RdpDomain)) = 'azuread', mirroring AzureAdCredentialDetector.HasAzureAdDomain
--     - LOWER(Username) LIKE 'azuread\%', mirroring AzureAdCredentialDetector.HasAzureAdPrefix
-- The '\' has no special meaning in SQLite LIKE, so the pattern matches the literal sequence
-- 'azuread\' followed by zero-or-more characters — including the bare 'azuread\' string,
-- which matches the C# StartsWith semantics.

UPDATE Nodes
SET RdpUseExternalClient = 1
WHERE Kind = 1
  AND Protocol = 1
  AND (RdpUseExternalClient IS NULL OR RdpUseExternalClient = 0)
  AND (
      LOWER(IFNULL(TRIM(RdpDomain), '')) = 'azuread'
      OR LOWER(IFNULL(Username, '')) LIKE 'azuread\%'
  );
