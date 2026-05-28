-- 0008_ssh_auto_sudo: opt-in flag for SSH connections that runs "sudo su" right after
-- the session connects, waits for the sudo password prompt, and sends the connection's
-- saved password. Lets users land directly in a root shell without re-typing the
-- password they already stored for the connection.
-- INTEGER NULL matches the existing boolean convention so values can inherit from a
-- parent folder when unset. MigrationRunner already wraps this in a transaction.

ALTER TABLE Nodes ADD COLUMN SshAutoSudo INTEGER NULL;
