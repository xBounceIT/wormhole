-- 0002_rdp_extras: full mstsc-style RDP setting columns on Nodes.
-- All columns nullable so values inherit from a parent folder when unset.
-- INTEGER NULL is used for booleans (0 / 1 / NULL) to match the existing convention.
-- MigrationRunner already wraps this script in a transaction; no explicit BEGIN/COMMIT.

-- Display
ALTER TABLE Nodes ADD COLUMN RdpColorDepth INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpUseAllMonitors INTEGER NULL;

-- Local Resources
ALTER TABLE Nodes ADD COLUMN RdpAudioMode INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpAudioCaptureMode INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpKeyboardHookMode INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectClipboard INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectPrinters INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectSmartCards INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectPorts INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectDevices INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpRedirectDrives TEXT NULL;

-- Experience
ALTER TABLE Nodes ADD COLUMN RdpConnectionSpeed INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpDesktopBackground INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpFontSmoothing INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpDesktopComposition INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpWindowDrag INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpMenuAnimation INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpVisualStyles INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpBitmapCaching INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpAutoReconnect INTEGER NULL;

-- Advanced
ALTER TABLE Nodes ADD COLUMN RdpServerAuthentication INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpGatewayUsageMethod INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpGatewayHostname TEXT NULL;
ALTER TABLE Nodes ADD COLUMN RdpGatewayCredentialId TEXT NULL;
ALTER TABLE Nodes ADD COLUMN RdpGatewayBypassLocal INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN RdpGatewayUseSameCreds INTEGER NULL;
