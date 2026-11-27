-- Version 58: reconcile a confirmed setup import across a client restart.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>57 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.workspace_import_receipts ADD COLUMN approval bytea, ADD COLUMN approval_signature bytea,
    ADD CHECK ((approval IS NULL AND approval_signature IS NULL) OR
        (octet_length(approval) IS NOT DISTINCT FROM 32 AND octet_length(approval_signature) IS NOT DISTINCT FROM 64));

CREATE FUNCTION wormhole_api_v1.setup_import_receipt(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_request uuid) RETURNS TABLE(approval bytea, signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $lookup$
DECLARE selected record;
BEGIN
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR p_request IS NULL THEN RAISE EXCEPTION 'Setup import receipt unavailable' USING ERRCODE='WH025'; END IF;
    RETURN QUERY SELECT r.approval,r.approval_signature FROM wormhole_data.workspace_import_receipts r
    WHERE r.actor_id=selected.actor AND r.request_id=p_request AND r.approval IS NOT NULL;
END
$lookup$;

-- An approval represents the exact source and reviewed destinations/pins.
-- The original import API still requires identical ciphertext for its retries.
CREATE FUNCTION wormhole_api_v1.commit_setup_import(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_request uuid,p_approval bytea,p_proof bytea,p_document text,p_signature bytea) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='25s' AS $commit$
DECLARE selected record; receipt wormhole_data.workspace_import_receipts; verdict text;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed'
        OR p_request IS NULL OR octet_length(p_approval) IS DISTINCT FROM 32 OR octet_length(p_proof) IS DISTINCT FROM 64
        OR COALESCE(octet_length(p_document),0) NOT BETWEEN 2 AND 134217728 OR octet_length(p_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid setup import' USING ERRCODE='WH025';
    END IF;
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND THEN RAISE EXCEPTION 'Setup import unavailable' USING ERRCODE='WH025'; END IF;
    SELECT r.* INTO receipt FROM wormhole_data.workspace_import_receipts r WHERE r.request_id=p_request;
    IF FOUND THEN
        IF receipt.actor_id=selected.actor AND receipt.approval=p_approval AND receipt.approval_signature=p_proof THEN
            RETURN 'already-imported';
        END IF;
        RAISE EXCEPTION 'Setup import approval changed' USING ERRCODE='WH028';
    END IF;
    verdict:=wormhole_data.commit_setup_import_graph(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,p_document,p_signature,p_request);
    IF verdict IS DISTINCT FROM 'imported' THEN RAISE EXCEPTION 'Setup import already allocated' USING ERRCODE='WH028'; END IF;
    UPDATE wormhole_data.workspace_import_receipts r SET approval=p_approval,approval_signature=p_proof
        WHERE r.request_id=p_request AND r.actor_id=selected.actor AND r.approval IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'Setup import receipt changed' USING ERRCODE='WH025'; END IF;
    RETURN verdict;
END
$commit$;

{{SETUP_IMPORT_GRAPH_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.commit_setup_import_graph(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,bytea,uuid)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.setup_import_receipt(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid),
    wormhole_api_v1.commit_setup_import(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bytea,bytea,text,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.setup_import_receipt(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid),
    wormhole_api_v1.commit_setup_import(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bytea,bytea,text,bytea)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=58 WHERE singleton;
COMMIT;
