-- 0004_rdp_use_external_client: opt-in flag for routing a connection through the
-- system Remote Desktop client (mstsc.exe) instead of the embedded ActiveX control.
-- The motivating case is Azure-AD-joined targets, where mstscax's delay-load of WAM
-- broker DLLs crashes the unpackaged WinUI process (SEH 0xC06D007F). Users mark
-- those connections with this flag to bypass the embedded host entirely.
-- INTEGER NULL matches the existing boolean convention so values can inherit from
-- a parent folder when unset. MigrationRunner already wraps this in a transaction.

ALTER TABLE Nodes ADD COLUMN RdpUseExternalClient INTEGER NULL;
