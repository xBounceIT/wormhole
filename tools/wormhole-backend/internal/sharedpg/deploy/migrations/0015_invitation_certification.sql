-- Version 15: public signed enrollment prerequisites, restricted to its invite.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>14 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.enrollment_certification(p_invite uuid,p_revision bigint,p_digest bytea)
RETURNS TABLE(signed_state bytea,state_sequence bigint,signed_profile bytea,
    enc_suite smallint,enc_public bytea,enc_signer_id uuid,enc_signer_version integer,enc_cert_revision bigint,enc_signature bytea,
    sign_suite smallint,sign_public bytea,sign_signer_id uuid,sign_signer_version integer,sign_cert_revision bigint,sign_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $certification$
DECLARE bootstrap record; invitation record; current_state record; profile bytea; enc record; sign record;
BEGIN
    SELECT * INTO STRICT bootstrap FROM wormhole_api_v1.enrollment_bootstrap(p_invite);
    IF p_revision IS NULL OR p_revision<>bootstrap.manifest_revision OR p_digest IS NULL
        OR pg_catalog.octet_length(p_digest)<>32 OR pg_catalog.sha256(bootstrap.manifest)<>p_digest THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    SELECT * INTO STRICT invitation FROM wormhole_data.invites WHERE id=p_invite;
    SELECT * INTO current_state FROM wormhole_data.user_key_states s WHERE s.user_id=invitation.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    SELECT m.signed_profile INTO profile FROM wormhole_data.workspace_meta m WHERE singleton;
    SELECT * INTO STRICT enc FROM wormhole_data.keys k WHERE k.key_id=invitation.bootstrap_enc_key_id AND k.key_version=invitation.bootstrap_enc_key_version FOR SHARE NOWAIT;
    SELECT * INTO STRICT sign FROM wormhole_data.keys k WHERE k.key_id=invitation.bootstrap_sign_key_id AND k.key_version=invitation.bootstrap_sign_key_version FOR SHARE NOWAIT;
    IF profile IS NULL OR enc.kind<>'user-enc' OR sign.kind<>'user-sign'
        OR enc.owner_id IS DISTINCT FROM invitation.user_id OR sign.owner_id IS DISTINCT FROM invitation.user_id
        OR enc.status<>'pending' OR sign.status<>'pending' OR enc.suite<>2 OR sign.suite<>1
        OR pg_catalog.octet_length(enc.public_key) IS DISTINCT FROM 32 OR pg_catalog.octet_length(sign.public_key) IS DISTINCT FROM 32
        OR enc.cert_revision IS NULL OR sign.cert_revision IS NULL
        OR enc.cert_signature IS NULL OR sign.cert_signature IS NULL
        OR enc.cert_signer_key_id IS DISTINCT FROM sign.cert_signer_key_id
        OR enc.cert_signer_key_version IS DISTINCT FROM sign.cert_signer_key_version
        OR NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=enc.cert_signer_key_id AND k.key_version=enc.cert_signer_key_version AND k.kind='org-sign') THEN
        RAISE EXCEPTION 'Enrollment certification unavailable' USING ERRCODE='WH010';
    END IF;
    RETURN QUERY SELECT current_state.signed_state,current_state.state_sequence,profile,
        enc.suite,enc.public_key,enc.cert_signer_key_id,enc.cert_signer_key_version,enc.cert_revision,enc.cert_signature,
        sign.suite,sign.public_key,sign.cert_signer_key_id,sign.cert_signer_key_version,sign.cert_revision,sign.cert_signature;
END
$certification$;
REVOKE ALL ON FUNCTION wormhole_api_v1.enrollment_certification(uuid,bigint,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.enrollment_certification(uuid,bigint,bytea) TO wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=15 WHERE singleton;
COMMIT;
