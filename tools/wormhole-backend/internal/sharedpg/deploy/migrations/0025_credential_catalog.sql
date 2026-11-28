-- Version 25: private sealed credential profiles, slots and personal bindings.
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
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>24 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Only authenticated writers may populate these records through future versioned
-- APIs. Table constraints bound structure; they do not authenticate signatures or
-- authorize Use/Write. Tombstones retain IDs and revision history.
CREATE FUNCTION wormhole_data.credential_fields_valid(p_fields jsonb,p_kind text,p_provider text,p_deleted boolean)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $fields$
DECLARE entry jsonb; previous text:=''; field_name text; version_text text;
BEGIN
    IF jsonb_typeof(p_fields) IS DISTINCT FROM 'array' OR p_kind IS NULL OR p_kind NOT IN ('password','sshKey')
       OR p_provider IS NULL OR p_provider NOT IN ('local','bitwarden') OR p_deleted IS NULL THEN RETURN false; END IF;
    IF jsonb_array_length(p_fields)>4 THEN RETURN false; END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_fields) LOOP
        IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR jsonb_typeof(entry->'field') IS DISTINCT FROM 'string'
           OR jsonb_typeof(entry->'version') IS DISTINCT FROM 'number' OR jsonb_typeof(entry->'present') IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
        field_name:=entry->>'field';version_text:=entry->>'version';
        IF field_name NOT IN ('password','passphrase','privateKey','certificate') OR field_name COLLATE "C"<=previous COLLATE "C"
           OR version_text !~ '^[1-9][0-9]{0,18}$' THEN RETURN false; END IF;
        IF version_text::numeric>9223372036854775807 THEN RETURN false; END IF;
        IF (entry->>'present')::boolean AND (p_deleted OR p_provider='bitwarden'
           OR (p_kind='password' AND field_name<>'password') OR (p_kind='sshKey' AND field_name='password')) THEN RETURN false; END IF;
        previous:=field_name;
    END LOOP;
    RETURN true;
END
$fields$;
CREATE TABLE wormhole_data.credential_profiles (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    owner_user_id uuid NULL REFERENCES wormhole_data.users(id),
    name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 1024 AND wormhole_data.resolver_text(name)<>''),
    protocol text NOT NULL CHECK(protocol IN ('ssh','rdp','vnc')),
    kind text NOT NULL CHECK(kind IN ('password','sshKey')),
    username text NOT NULL DEFAULT '' CHECK(octet_length(username)<=2048),
    domain text NOT NULL DEFAULT '' CHECK(octet_length(domain)<=2048),
    provider text NOT NULL CHECK(provider IN ('local','bitwarden')),
    bitwarden_item_id text NOT NULL DEFAULT '' CHECK(octet_length(bitwarden_item_id)<=2048),
    bitwarden_item_name text NOT NULL DEFAULT '' CHECK(octet_length(bitwarden_item_name)<=4096),
    bitwarden_field_path text NOT NULL DEFAULT '' CHECK(octet_length(bitwarden_field_path)<=2048),
    private_key_name text NOT NULL DEFAULT '' CHECK(octet_length(private_key_name)<=1024),
    certificate_name text NOT NULL DEFAULT '' CHECK(octet_length(certificate_name)<=1024),
    fields jsonb NOT NULL DEFAULT '[]' CHECK(octet_length(fields::text)<=2048),
    boundary_id uuid NOT NULL CHECK(boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    deleted boolean NOT NULL DEFAULT false,
    seal_suite smallint NOT NULL CHECK(seal_suite=2),
    seal_signer_key_id uuid NOT NULL,
    seal_signer_key_version integer NOT NULL,
    seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    seal bytea NOT NULL CHECK(octet_length(seal)=64),
    FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK(kind<>'sshKey' OR protocol='ssh'),
    CHECK(provider<>'local' OR (bitwarden_item_id='' AND bitwarden_item_name='' AND bitwarden_field_path='')),
    CHECK(provider<>'bitwarden' OR (bitwarden_item_id<>'' AND kind='password' AND private_key_name='' AND certificate_name='')),
    CHECK(wormhole_data.credential_fields_valid(fields,kind,provider,deleted))
);
CREATE UNIQUE INDEX credential_profiles_owner_name ON wormhole_data.credential_profiles
    (COALESCE(owner_user_id,'00000000-0000-0000-0000-000000000000'::uuid),name) WHERE NOT deleted;
CREATE TABLE wormhole_data.credential_slots (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 1024 AND wormhole_data.resolver_text(name)<>''),
    protocol text NOT NULL CHECK(protocol IN ('ssh','rdp','vnc')),
    default_credential_id uuid NULL REFERENCES wormhole_data.credential_profiles(id),
    allow_self_service boolean NOT NULL DEFAULT false,
    boundary_id uuid NOT NULL CHECK(boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    deleted boolean NOT NULL DEFAULT false,
    seal_suite smallint NOT NULL CHECK(seal_suite=2),
    seal_signer_key_id uuid NOT NULL,
    seal_signer_key_version integer NOT NULL,
    seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    seal bytea NOT NULL CHECK(octet_length(seal)=64),
    FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);
CREATE TABLE wormhole_data.credential_slot_values (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    slot_id uuid NOT NULL REFERENCES wormhole_data.credential_slots(id),
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    credential_id uuid NULL REFERENCES wormhole_data.credential_profiles(id),
    boundary_id uuid NOT NULL CHECK(boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    deleted boolean NOT NULL DEFAULT false,
    seal_suite smallint NOT NULL CHECK(seal_suite=2),
    seal_signer_key_id uuid NOT NULL,
    seal_signer_key_version integer NOT NULL,
    seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    seal bytea NOT NULL CHECK(octet_length(seal)=64),
    FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    UNIQUE(slot_id,user_id),
    CHECK(deleted OR credential_id IS NOT NULL)
);
CREATE TABLE wormhole_data.user_node_overrides (
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    node_id uuid NOT NULL REFERENCES wormhole_data.nodes(id),
    credential_id uuid NULL REFERENCES wormhole_data.credential_profiles(id),
    boundary_id uuid NOT NULL CHECK(boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    deleted boolean NOT NULL DEFAULT false,
    seal_suite smallint NOT NULL CHECK(seal_suite=2),
    seal_signer_key_id uuid NOT NULL,
    seal_signer_key_version integer NOT NULL,
    seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    seal bytea NOT NULL CHECK(octet_length(seal)=64),
    FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    PRIMARY KEY(user_id,node_id),
    CHECK(deleted OR credential_id IS NOT NULL)
);
-- The same snapshot lock protects nodes, account choices and signing state.
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.credential_profiles
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.credential_slots
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.credential_slot_values
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.user_node_overrides
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
-- Ciphertext/copy changes also participate: a release must not combine a signed
-- account snapshot with key material from a concurrent transaction.
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.secret_values
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.key_copies
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
REVOKE ALL ON TABLE wormhole_data.credential_profiles,wormhole_data.credential_slots,
    wormhole_data.credential_slot_values,wormhole_data.user_node_overrides FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_data.credential_fields_valid(jsonb,text,text,boolean) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=25 WHERE singleton;
COMMIT;
