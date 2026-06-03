-- 0010_inline_password: opt-in flag marking a connection that authenticates with an
-- inline, per-connection password the user typed directly in the editor (instead of
-- picking a saved credential or being prompted every time). The password itself is NOT
-- stored here — it lives in Windows Credential Manager keyed by the node Id
-- (key "Wormhole:<nodeId>"), exactly like a saved credential's secret. This column only
-- records whether such a secret exists. SSH-only today; RDP ignores it.
-- INTEGER NULL matches the existing boolean convention (treated as false when unset).
-- MigrationRunner already wraps this in a transaction.

ALTER TABLE Nodes ADD COLUMN UseInlinePassword INTEGER NULL;
