-- Version 80: register replacement keys and the new device in one transaction.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>79 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.install_replacement_enrollment(request wormhole_data.account_reset_offers,p_certificate bytea)
RETURNS TABLE(encryption_id uuid,signing_id uuid)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $install$
DECLARE bootstrap json; chain jsonb; proof jsonb; enc uuid; sig uuid; enc_public bytea; sig_public bytea;
BEGIN
    IF octet_length(p_certificate) IS NULL OR octet_length(p_certificate) NOT BETWEEN 1 AND 32768 THEN
        RAISE EXCEPTION 'Invalid account replacement certificate' USING ERRCODE='WH008';
    END IF;
    BEGIN
        bootstrap:=convert_from(request.replacement,'UTF8')::json;
        chain:=convert_from(p_certificate,'UTF8')::jsonb;
        proof:=chain->'rekey';
        enc:=(proof->>'encryptionKeyId')::uuid;
        sig:=(proof->>'signingKeyId')::uuid;
        enc_public:=decode(proof#>>'{public,encryption}','base64');
        sig_public:=decode(proof#>>'{public,signing}','base64');
        IF chain->>'formatVersion' IS DISTINCT FROM '1' OR
           chain->'manifest' IS DISTINCT FROM (bootstrap->'manifest')::jsonb OR
           chain->'bootstrapEncryption' IS DISTINCT FROM (bootstrap->'encryption')::jsonb OR
           chain->'bootstrapSigning' IS DISTINCT FROM (bootstrap->'signing')::jsonb OR
           proof->>'formatVersion' IS DISTINCT FROM '1' OR proof->>'keyVersion' IS DISTINCT FROM '1' OR
           octet_length(decode(proof->>'signature','base64')) IS DISTINCT FROM 64 OR
           octet_length(enc_public) IS DISTINCT FROM 32 OR octet_length(sig_public) IS DISTINCT FROM 32 OR
           enc IS NULL OR sig IS NULL OR enc=sig OR EXISTS(
               SELECT FROM unnest(ARRAY[enc,sig]) AS ids(id) WHERE id IN (
                   '00000000-0000-0000-0000-000000000000'::uuid,
                   (bootstrap#>>'{state,encryption,id}')::uuid,(bootstrap#>>'{state,signing,id}')::uuid,
                   (bootstrap#>>'{state,signer,id}')::uuid,
                   (request.subject#>>'{encryption,id}')::uuid,(request.subject#>>'{signing,id}')::uuid)) OR
           enc_public=decode(bootstrap#>>'{manifest,bootstrap,encryption}','base64') OR
           sig_public=decode(bootstrap#>>'{manifest,bootstrap,signing}','base64') OR EXISTS(
               SELECT FROM wormhole_data.keys k WHERE k.owner_id=request.user_id
               AND ((k.kind='user-enc' AND k.public_key=enc_public) OR (k.kind='user-sign' AND k.public_key=sig_public))) THEN
            RAISE EXCEPTION 'Invalid certificate';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid account replacement certificate' USING ERRCODE='WH008';
    END;
    UPDATE wormhole_data.keys k SET status='retired'
      WHERE k.owner_id=request.user_id AND k.status='active' AND k.kind IN ('user-enc','user-sign');
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
      VALUES(enc,1,'user-enc',request.user_id,2,enc_public),(sig,1,'user-sign',request.user_id,1,sig_public);
    UPDATE wormhole_data.user_enrollments e SET encryption_key_id=enc,encryption_key_version=1,
        signing_key_id=sig,signing_key_version=1,certificate=p_certificate WHERE e.user_id=request.user_id;
    -- Keep the exact bytes from the signed offer. jsonb would reorder them.
    UPDATE wormhole_data.user_key_states s SET state_sequence=(bootstrap#>>'{state,sequence}')::bigint,
        signed_state=convert_to((bootstrap->'state')::text,'UTF8') WHERE s.user_id=request.user_id;
    RETURN QUERY SELECT enc,sig;
END
$install$;

{{REDEEM_ACCOUNT_REENROLLMENT}}

-- The new SCRAM login may reconcile the exact persisted submission while the
-- account is still disabled. Regular device admission remains unavailable.
CREATE FUNCTION wormhole_api_v1.account_reenrollment_receipt(
    p_offer uuid,p_offer_hash bytea,p_device uuid,p_capsule_digest bytea,p_certificate_digest bytea)
RETURNS TABLE(wrap_revision bigint,auth_epoch bigint,suspended boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $receipt$
BEGIN
    RETURN QUERY SELECT r.wrap_revision,r.auth_epoch,u.disabled
    FROM wormhole_data.account_reset_receipts r
    JOIN wormhole_data.account_reset_offers o ON o.id=r.offer_id
    JOIN wormhole_data.users u ON u.id=o.user_id
    JOIN wormhole_data.devices d ON d.id=r.device_id AND d.user_id=u.id
    JOIN wormhole_data.device_confirmations c ON c.device_id=d.id
    JOIN pg_catalog.pg_roles role ON role.oid=c.role_oid AND role.rolname=d.role_name
    JOIN wormhole_data.user_key_wraps w ON w.user_id=u.id
    JOIN wormhole_data.user_enrollments e ON e.user_id=u.id
    JOIN wormhole_data.account_auth a ON a.user_id=u.id
    JOIN wormhole_data.workspace_meta m ON m.singleton
    WHERE o.id=p_offer AND o.offer_hash=p_offer_hash AND o.replacement IS NOT NULL AND o.retired_at IS NOT NULL
      AND d.id=p_device AND d.role_name=session_user AND d.status='active'
      AND role.rolcanlogin AND role.rolvaliduntil='infinity'::timestamptz AND NOT role.rolinherit
      AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
      AND w.wrap_revision=r.wrap_revision AND a.auth_epoch=r.auth_epoch AND w.ask_required
      AND sha256(convert_to('wormhole/v1/pending-enrollment-capsule','UTF8')||w.nonce||w.ciphertext)=p_capsule_digest
      AND c.certificate_digest=p_certificate_digest AND sha256(e.certificate)=p_certificate_digest
      AND m.state='ready' AND m.require_tls AND m.min_api<=1 AND m.max_api>=1
      AND sha256(m.tls_bundle)=o.tls_hash AND sha256(m.signed_profile)=o.policy_hash
      AND COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false);
    IF NOT FOUND THEN RAISE EXCEPTION 'Account replacement receipt is unavailable' USING ERRCODE='WH023'; END IF;
END
$receipt$;

REVOKE ALL ON FUNCTION wormhole_data.install_replacement_enrollment(wormhole_data.account_reset_offers,bytea),
    wormhole_api_v1.redeem_account_reenrollment(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea,bytea),
    wormhole_api_v1.account_reenrollment_receipt(uuid,bytea,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.redeem_account_reenrollment(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea,bytea)
    TO wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reenrollment_receipt(uuid,bytea,uuid,bytea,bytea) TO wh_{{TAG}}_user;

{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=80 WHERE singleton;
COMMIT;
