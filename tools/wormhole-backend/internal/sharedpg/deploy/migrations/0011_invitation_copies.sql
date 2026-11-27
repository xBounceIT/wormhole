-- Version 11: bounded, revision-bound download of bootstrap key copies.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>10 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.enrollment_key_copies(p_invite uuid,p_revision bigint,p_manifest_digest bytea)
RETURNS TABLE(key_id uuid,key_version integer,holder_key_id uuid,holder_key_version integer,
    issuer_key_id uuid,issuer_key_version integer,suite smallint,enc bytea,ciphertext bytea,signature bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $copies$
DECLARE bootstrap record; item record; copy_count integer:=0;
BEGIN
    -- Reuse the complete invitation/role/TLS gate, holding its row locks through
    -- this read. session_user remains the original temporary login.
    SELECT * INTO STRICT bootstrap FROM wormhole_api_v1.enrollment_bootstrap(p_invite);
    IF p_revision IS NULL OR p_revision<>bootstrap.manifest_revision OR p_manifest_digest IS NULL
       OR pg_catalog.octet_length(p_manifest_digest)<>32 OR pg_catalog.sha256(bootstrap.manifest)<>p_manifest_digest THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    -- One cursor snapshot for validation and return: separate count/shape/read
    -- statements could observe different committed copies at READ COMMITTED.
    FOR item IN SELECT c.* FROM wormhole_data.key_copies c WHERE c.holder_key_id=bootstrap.bootstrap_key_id
        AND c.holder_key_version=bootstrap.bootstrap_key_version ORDER BY c.key_id,c.key_version LIMIT 1025 LOOP
        copy_count:=copy_count+1;
        IF copy_count>1024 OR item.suite<>2 OR item.enc IS NULL OR pg_catalog.octet_length(item.enc)<>32
           OR pg_catalog.octet_length(item.ciphertext)<>48 OR pg_catalog.octet_length(item.signature)<>64 THEN
            RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
        END IF;
        key_id:=item.key_id; key_version:=item.key_version;
        holder_key_id:=item.holder_key_id; holder_key_version:=item.holder_key_version;
        issuer_key_id:=item.issuer_key_id; issuer_key_version:=item.issuer_key_version;
        suite:=item.suite; enc:=item.enc; ciphertext:=item.ciphertext; signature:=item.signature;
        RETURN NEXT;
    END LOOP;
END
$copies$;
REVOKE ALL ON FUNCTION wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.enrollment_key_copies(uuid,bigint,bytea) TO wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=11 WHERE singleton;
COMMIT;
