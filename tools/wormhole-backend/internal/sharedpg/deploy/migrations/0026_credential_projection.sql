-- Version 26: private signed credential snapshot projection.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>25 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Only a connection-authorized release API may expose this projection. No
-- credential-ID-based public API or secret release is granted by this helper.
CREATE FUNCTION wormhole_data.credential_record(p_credential uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,credential_id uuid,epoch bigint,change_seq bigint,
    record jsonb,boundary_id uuid,row_version bigint,seal_suite smallint,seal_signer_key_id uuid,
    seal_signer_key_version integer,seal_capability_id uuid,seal bytea,
    author_id uuid,signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $credential$
DECLARE meta record; item wormhole_data.credential_profiles; author record; projected jsonb;
BEGIN
    IF p_credential IS NULL OR p_credential='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid credential request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013';
    END IF;
    SELECT c.* INTO item FROM wormhole_data.credential_profiles c WHERE c.id=p_credential;
    IF NOT FOUND THEN RAISE EXCEPTION 'Credential metadata unavailable' USING ERRCODE='WH018'; END IF;
    projected:=jsonb_build_object('metadata',jsonb_build_object(
        'id',item.id,'ownerUserId',COALESCE(item.owner_user_id::text,''),'name',item.name,
        'protocol',item.protocol,'kind',item.kind,'username',item.username,'domain',item.domain,
        'provider',item.provider,'bitwardenItemId',item.bitwarden_item_id,'bitwardenItemName',item.bitwarden_item_name,
        'bitwardenFieldPath',item.bitwarden_field_path,'privateKeyName',item.private_key_name,'certificateName',item.certificate_name),
        'deleted',item.deleted,'fields',item.fields);
    IF octet_length(projected::text)>131072 THEN RAISE EXCEPTION 'Credential projection is too large' USING ERRCODE='54000'; END IF;
    SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    -- Tombstones and current signed revocations are returned for native floors.
    -- No secret envelope, key copy or account capsule is part of this projection.
    RETURN QUERY SELECT meta.workspace_id,item.id,meta.epoch,meta.change_seq,projected,
        item.boundary_id,item.row_version,item.seal_suite,item.seal_signer_key_id,item.seal_signer_key_version,item.seal_capability_id,item.seal,
        author.author_id,author.signing_key_id,author.signing_key_version,author.state_sequence,author.signed_state,
        author.suite,author.public_key,author.cert_signer_key_id,author.cert_signer_key_version,author.cert_revision,author.cert_signature;
END
$credential$;
REVOKE ALL ON FUNCTION wormhole_data.credential_record(uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=26 WHERE singleton;
COMMIT;
