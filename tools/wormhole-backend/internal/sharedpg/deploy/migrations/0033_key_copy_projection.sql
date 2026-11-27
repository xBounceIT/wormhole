-- Version 33: private snapshot-bound key copies with issuer material.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>32 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Internal graph projection, never a raw-key public API. Caller selects an
-- expected key and holder from authenticated connection/boundary/account material.
CREATE FUNCTION wormhole_data.key_copy_record(p_key uuid,p_version integer,p_holder uuid,p_holder_version integer,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,epoch bigint,change_seq bigint,key_id uuid,key_version integer,
    holder_key_id uuid,holder_key_version integer,suite smallint,enc bytea,ciphertext bytea,
    issuer_key_id uuid,issuer_key_version integer,signature bytea,issuer_kind text,
    author_id uuid,state_sequence bigint,signed_state bytea,cert_suite smallint,cert_public bytea,
    cert_signer_id uuid,cert_signer_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $copy$
DECLARE meta record; item wormhole_data.key_copies; issuer record; author record;
BEGIN
    IF p_key IS NULL OR p_key='00000000-0000-0000-0000-000000000000'::uuid
       OR p_holder IS NULL OR p_holder='00000000-0000-0000-0000-000000000000'::uuid
       OR p_version IS NULL OR p_version<1 OR p_holder_version IS NULL OR p_holder_version<1
       OR (p_key=p_holder AND p_version=p_holder_version)
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid key-copy request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004'; END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013'; END IF;
    SELECT c.* INTO item FROM wormhole_data.key_copies c WHERE c.key_id=p_key AND c.key_version=p_version AND c.holder_key_id=p_holder AND c.holder_key_version=p_holder_version;
    IF NOT FOUND THEN RAISE EXCEPTION 'Key copy unavailable' USING ERRCODE='WH010'; END IF;
    IF item.suite<>2 OR item.enc IS NULL OR octet_length(item.enc)<>32 OR octet_length(item.ciphertext)<>48 THEN RAISE EXCEPTION 'Key copy unsupported' USING ERRCODE='WH010'; END IF;
    SELECT k.kind INTO STRICT issuer FROM wormhole_data.keys k WHERE k.key_id=item.issuer_key_id AND k.key_version=item.issuer_key_version;
    IF issuer.kind='org-sign' THEN
        RETURN QUERY SELECT meta.workspace_id,meta.epoch,meta.change_seq,item.key_id,item.key_version,item.holder_key_id,item.holder_key_version,item.suite,item.enc,item.ciphertext,item.issuer_key_id,item.issuer_key_version,item.signature,issuer.kind,
            NULL::uuid,NULL::bigint,NULL::bytea,NULL::smallint,NULL::bytea,NULL::uuid,NULL::integer,NULL::bigint,NULL::bytea;
    ELSIF issuer.kind='user-sign' THEN
        SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.issuer_key_id,item.issuer_key_version);
        RETURN QUERY SELECT meta.workspace_id,meta.epoch,meta.change_seq,item.key_id,item.key_version,item.holder_key_id,item.holder_key_version,item.suite,item.enc,item.ciphertext,item.issuer_key_id,item.issuer_key_version,item.signature,issuer.kind,
            author.author_id,author.state_sequence,author.signed_state,author.suite,author.public_key,author.cert_signer_key_id,author.cert_signer_key_version,author.cert_revision,author.cert_signature;
    ELSE RAISE EXCEPTION 'Key copy issuer unavailable' USING ERRCODE='WH010';
    END IF;
END
$copy$;
REVOKE ALL ON FUNCTION wormhole_data.key_copy_record(uuid,integer,uuid,integer,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=33 WHERE singleton;
COMMIT;
