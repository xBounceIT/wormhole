-- 0003_add_tunnel_config: per-connection in-process VPN tunnel support.
--
-- TunnelEnabled is tri-state (NULL = inherit from ancestor folder, 0 = off, 1 = on),
-- matching the existing RdpFullScreen shape so InheritanceResolver can treat it the same.
-- TunnelConfigId references a row in TunnelConfigs whose actual secrets (WireGuard private
-- key, peer pubkey, endpoint) live DPAPI-encrypted on disk under
-- %LOCALAPPDATA%\Wormhole\tunnels\<id>.dpapi -- not in the DB. Same split as
-- CredentialProfiles + the keys/ directory.

ALTER TABLE Nodes ADD COLUMN TunnelEnabled INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN TunnelConfigId TEXT NULL;

-- Partial index: the tunnel-delete reference check needs "find nodes pointing at this
-- TunnelConfigId" cheaply. Restricting to non-null rows keeps the index small because the
-- vast majority of connections don't opt into a tunnel.
CREATE INDEX IX_Nodes_TunnelConfigId ON Nodes(TunnelConfigId) WHERE TunnelConfigId IS NOT NULL;

CREATE TABLE TunnelConfigs (
    Id         TEXT     PRIMARY KEY NOT NULL,
    Name       TEXT     NOT NULL,
    Kind       INTEGER  NOT NULL,
    CreatedAt  TEXT     NOT NULL,
    UpdatedAt  TEXT     NOT NULL
);

CREATE UNIQUE INDEX UX_TunnelConfigs_Name ON TunnelConfigs(Name);
