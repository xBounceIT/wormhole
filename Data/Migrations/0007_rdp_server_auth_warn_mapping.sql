-- 0007_rdp_server_auth_warn_mapping: previous builds displayed value 0 as "Warn",
-- but mstscax AuthenticationLevel=0 means no server authentication, while old value 2
-- was the editor's explicit fail-closed option. Preserve both user intents:
--   old 0 (default/warn) -> new 2 (warn/prompt)
--   old 2 (fail closed)  -> new 1 (require server authentication)
UPDATE Nodes
SET RdpServerAuthentication = CASE RdpServerAuthentication
    WHEN 0 THEN 2
    WHEN 2 THEN 1
    ELSE RdpServerAuthentication
END
WHERE RdpServerAuthentication IN (0, 2);
