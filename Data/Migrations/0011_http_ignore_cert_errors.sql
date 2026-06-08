-- 0011_http_ignore_cert_errors: opt-in flag for the HTTPS web protocol marking a connection
-- whose embedded WebView2 browser should accept certificate errors (self-signed, name mismatch,
-- untrusted chain) when navigating. The motivating case is appliance GUIs — firewalls and the
-- like — that serve self-signed certs, typically reached through a per-connection VPN tunnel.
-- Inheritable from a parent folder like the other connection settings; only consulted for HTTPS.
-- INTEGER NULL matches the existing boolean convention (treated as false when unset).
-- MigrationRunner already wraps this in a transaction.

ALTER TABLE Nodes ADD COLUMN HttpIgnoreCertErrors INTEGER NULL;
