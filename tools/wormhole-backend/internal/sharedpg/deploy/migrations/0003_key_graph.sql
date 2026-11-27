-- Version 3: private key graph and enrollment records. No runtime DDL or table grants.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
DO $migration_lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$migration_lock$;
SET LOCAL timezone = 'UTC';
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 2 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE = '55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.keys (
    key_id uuid NOT NULL CHECK (key_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    key_version integer NOT NULL CHECK (key_version >= 1),
    kind text NOT NULL CHECK (kind IN ('user-enc','user-sign','device','group','org-enc','org-sign',
        'recovery','recovery-share','boundary-view','boundary-secret','boundary-write','dek','vault')),
    owner_id uuid NULL CHECK (owner_id IS NULL OR owner_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending','active','rotating','retired')),
    suite smallint NOT NULL CHECK (suite > 0),
    public_key bytea NULL CHECK (public_key IS NULL OR pg_catalog.octet_length(public_key) BETWEEN 1 AND 4096),
    cert_signer_key_id uuid NULL,
    cert_signer_key_version integer NULL,
    cert_signature bytea NULL CHECK (cert_signature IS NULL OR pg_catalog.octet_length(cert_signature)=64),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    PRIMARY KEY(key_id,key_version),
    FOREIGN KEY(cert_signer_key_id,cert_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    CHECK (pg_catalog.num_nonnulls(cert_signer_key_id,cert_signer_key_version,cert_signature) IN (0,3))
);
CREATE UNIQUE INDEX keys_one_active ON wormhole_data.keys
    (kind,COALESCE(owner_id,'00000000-0000-0000-0000-000000000000'::uuid)) WHERE status='active';

CREATE TABLE wormhole_data.key_copies (
    key_id uuid NOT NULL,
    key_version integer NOT NULL,
    holder_key_id uuid NOT NULL,
    holder_key_version integer NOT NULL,
    suite smallint NOT NULL CHECK (suite > 0),
    enc bytea NULL CHECK (enc IS NULL OR pg_catalog.octet_length(enc) BETWEEN 1 AND 4096),
    ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(ciphertext) BETWEEN 16 AND 4194320),
    issuer_key_id uuid NOT NULL,
    issuer_key_version integer NOT NULL,
    signature bytea NOT NULL CHECK (pg_catalog.octet_length(signature)=64),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY(key_id,key_version,holder_key_id,holder_key_version),
    FOREIGN KEY(key_id,key_version) REFERENCES wormhole_data.keys(key_id,key_version) ON DELETE CASCADE,
    FOREIGN KEY(holder_key_id,holder_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    FOREIGN KEY(issuer_key_id,issuer_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK (NOT (key_id=holder_key_id AND key_version=holder_key_version))
);
CREATE INDEX key_copies_holder ON wormhole_data.key_copies(holder_key_id,holder_key_version);

CREATE TABLE wormhole_data.secret_values (
    owner_kind text NOT NULL CHECK (owner_kind IN ('credential','node','tunnel','slot-value')),
    owner_id uuid NOT NULL CHECK (owner_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    field text NOT NULL CHECK (pg_catalog.octet_length(field) BETWEEN 1 AND 1024),
    dek_id uuid NOT NULL,
    dek_version integer NOT NULL,
    envelope bytea NOT NULL CHECK (pg_catalog.octet_length(envelope) BETWEEN 16 AND 8388608),
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1),
    PRIMARY KEY(owner_kind,owner_id,field),
    FOREIGN KEY(dek_id,dek_version) REFERENCES wormhole_data.keys(key_id,key_version)
);

CREATE TABLE wormhole_data.invites (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id) CHECK (user_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    kind text NOT NULL CHECK (kind IN ('invite','reset')),
    code_hash bytea NOT NULL CHECK (pg_catalog.octet_length(code_hash)=32),
    created_by uuid NOT NULL REFERENCES wormhole_data.users(id) CHECK (created_by <> '00000000-0000-0000-0000-000000000000'::uuid),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp() CHECK (pg_catalog.isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(expires_at)),
    used_at timestamptz NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    bootstrap_enc_key_id uuid NOT NULL,
    bootstrap_enc_key_version integer NOT NULL,
    bootstrap_sign_key_id uuid NOT NULL,
    bootstrap_sign_key_version integer NOT NULL,
    bootstrap_envelope bytea NOT NULL CHECK (pg_catalog.octet_length(bootstrap_envelope) BETWEEN 16 AND 65536),
    manifest bytea NOT NULL CHECK (pg_catalog.octet_length(manifest) BETWEEN 2 AND 1048576),
    manifest_revision bigint NOT NULL CHECK (manifest_revision >= 1),
    manifest_digest bytea GENERATED ALWAYS AS (pg_catalog.sha256(manifest)) STORED,
    FOREIGN KEY(bootstrap_enc_key_id,bootstrap_enc_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    FOREIGN KEY(bootstrap_sign_key_id,bootstrap_sign_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK (expires_at > created_at),
    CHECK (used_at IS NULL OR (pg_catalog.isfinite(used_at) AND used_at >= created_at AND used_at <= expires_at)),
    CHECK (bootstrap_enc_key_id <> bootstrap_sign_key_id)
);
CREATE INDEX invites_user ON wormhole_data.invites(user_id,expires_at);

REVOKE ALL ON TABLE wormhole_data.keys,wormhole_data.key_copies,wormhole_data.secret_values,wormhole_data.invites
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
UPDATE wormhole_data.workspace_meta SET schema_version=3 WHERE singleton;
COMMIT;
