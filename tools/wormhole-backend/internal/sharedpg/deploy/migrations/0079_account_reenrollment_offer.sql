-- Version 79: a scoped bootstrap for replacing a suspended account's keys.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>78 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.account_reset_offers
    ADD COLUMN replacement bytea CHECK(octet_length(replacement) BETWEEN 1 AND 32768),
    ADD CHECK((replacement IS NOT NULL)=(subject ? 'suspension'));

CREATE FUNCTION wormhole_data.account_reenrollment_target(p_account uuid,p_suspension bigint) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $target$
DECLARE target record; boundary uuid;
BEGIN
    boundary:=wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,p_account);
    SELECT u.id,u.login_name,e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version,
           w.wrap_revision,w.kdf_preset,e.certificate,state.signed_state,state.state_sequence
    INTO target FROM wormhole_data.users u
    JOIN wormhole_data.account_suspensions s ON s.account_id=u.id
    JOIN wormhole_data.account_suspension_enrollments p ON p.account_id=u.id
    JOIN wormhole_data.user_enrollments e ON e.user_id=u.id
    JOIN wormhole_data.user_key_wraps w ON w.user_id=u.id
    JOIN wormhole_data.user_key_states state ON state.user_id=u.id
    WHERE u.id=p_account AND u.disabled AND s.revision=p_suspension
      AND (p.encryption_key_id,p.encryption_key_version,p.signing_key_id,p.signing_key_version)=
          (e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version)
      AND (w.encryption_key_id,w.encryption_key_version,w.signing_key_id,w.signing_key_version)=
          (e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version)
      AND state.state_sequence=p.state_sequence AND sha256(state.signed_state)=p.state_digest
      AND convert_from(state.signed_state,'UTF8')::jsonb->>'active'='true'
      AND w.wrap_revision<9223372036854775807 AND state.state_sequence<9223372036854775807
      AND EXISTS(SELECT FROM wormhole_data.boundaries b WHERE b.id=boundary AND b.owner_user_id=p_account AND NOT b.deleted)
      AND 2=(SELECT count(*) FROM wormhole_data.account_suspension_roots r JOIN wormhole_data.keys k
          ON (k.key_id,k.key_version)=(r.root_id,r.root_version) WHERE r.account_id=p_account AND r.boundary_id=boundary AND k.status='retired')
    FOR SHARE OF u,s,p,e,w,state NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account replacement unavailable' USING ERRCODE='WH023'; END IF;
    RETURN jsonb_build_object('userId',target.id,'loginName',target.login_name,
        'encryption',jsonb_build_object('id',target.encryption_key_id,'version',target.encryption_key_version),
        'signing',jsonb_build_object('id',target.signing_key_id,'version',target.signing_key_version),
        'wrapRevision',target.wrap_revision,'minimumKdf',target.kdf_preset,'suspension',p_suspension,'accountSequence',target.state_sequence,
        'certificateDigest',encode(sha256(target.certificate),'base64'),'stateDigest',encode(sha256(target.signed_state),'base64'));
END
$target$;

CREATE FUNCTION wormhole_api_v1.account_reenrollment_material(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,p_account uuid,p_suspension bigint)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE actor record; subject jsonb; state bytea; certificate bytea; copies jsonb;
BEGIN
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR NOT actor.custodian OR actor.recipient_signature IS NULL OR NOT wormhole_data.personal_account_rotation_available(
        actor.actor,p_account,wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,p_account)) THEN
        RAISE EXCEPTION 'Account replacement unavailable' USING ERRCODE='WH023';
    END IF;
    subject:=wormhole_data.account_reenrollment_target(p_account,p_suspension);
    SELECT e.certificate,s.signed_state INTO STRICT certificate,state
      FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_states s USING(user_id) WHERE e.user_id=p_account;
    SELECT jsonb_agg(jsonb_build_object('id',c.org_key_id,'version',c.org_key_version,'enc',encode(c.enc,'base64'),
        'ciphertext',encode(c.ciphertext,'base64'),'signature',encode(c.signature,'base64'))) INTO copies
    FROM (VALUES ('org-enc'),('org-sign')) k(kind)
    CROSS JOIN LATERAL wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,k.kind) c;
    IF jsonb_array_length(copies) IS DISTINCT FROM 2 THEN RAISE EXCEPTION 'Account replacement unavailable' USING ERRCODE='WH023'; END IF;
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'account_reenrollment_material','key_copies_released');
    RETURN jsonb_build_object('roleTag','{{TAG}}','database',current_database(),'subject',subject,
        'signedState',encode(state,'base64'),'enrollment',encode(certificate,'base64'),'copies',copies,
        'recipient',jsonb_build_object('id',actor.recipient_id,'version',actor.recipient_version),
        'recipientPublic',encode(actor.recipient_public,'base64'),'recipientProof',encode(actor.recipient_signature,'base64'));
END
$material$;

CREATE FUNCTION wormhole_data.reenrollment_bootstrap_matches(p_bootstrap bytea,p_subject jsonb,p_offer uuid,p_expires bigint)
RETURNS boolean LANGUAGE sql STABLE STRICT SET search_path=pg_catalog,pg_temp AS $bootstrap$
    SELECT coalesce(
        body#>>'{manifest,context,workspaceId}'='{{WORKSPACE_ID}}'
        AND body#>>'{manifest,context,userId}'=p_subject->>'userId'
        AND body#>>'{manifest,context,loginName}'=p_subject->>'loginName'
        AND body#>>'{manifest,context,inviteId}'=p_offer::text
        AND body#>>'{manifest,expiresAt}'=p_expires::text
        AND body#>>'{state,workspaceId}'='{{WORKSPACE_ID}}'
        AND body#>>'{state,userId}'=p_subject->>'userId'
        AND body#>>'{state,sequence}'=((p_subject->>'accountSequence')::bigint+1)::text
        AND body#>>'{state,active}'='true'
        AND body#>>'{manifest,context,keyId}'=body#>>'{state,encryption,id}'
        AND body#>>'{manifest,context,keyVersion}'=body#>>'{state,encryption,version}'
        AND body#>'{state,encryption}'=body#>'{encryption,key}'
        AND body#>'{state,signing}'=body#>'{signing,key}',false)
    FROM (SELECT convert_from(p_bootstrap,'UTF8')::jsonb AS body) bootstrap;
$bootstrap$;

{{PUBLISH_ACCOUNT_REENROLLMENT}}
{{REQUIRE_ACCOUNT_REENROLLMENT}}

CREATE FUNCTION wormhole_api_v1.account_reenrollment_capsule(p_offer uuid,p_offer_hash bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $capsule$
DECLARE request wormhole_data.account_reset_offers;
BEGIN
    request:=wormhole_data.require_account_reenrollment(p_offer,p_offer_hash,false);
    PERFORM wormhole_data.audit_server_ca(request.user_id,request.id,'reset-v2','account_reenrollment_capsule','released');
    RETURN request.capsule;
END
$capsule$;

REVOKE ALL ON FUNCTION wormhole_data.account_reenrollment_target(uuid,bigint),wormhole_data.require_account_reenrollment(uuid,bytea,boolean),
    wormhole_data.reenrollment_bootstrap_matches(bytea,jsonb,uuid,bigint),
    wormhole_api_v1.account_reenrollment_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint),
    wormhole_api_v1.publish_account_reenrollment(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,jsonb,bigint,bytea,bytea,bytea,text,bytea),
    wormhole_api_v1.account_reenrollment_capsule(uuid,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reenrollment_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint),
    wormhole_api_v1.publish_account_reenrollment(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,jsonb,bigint,bytea,bytea,bytea,text,bytea)
    TO wh_{{TAG}}_user;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reenrollment_capsule(uuid,bytea) TO wh_{{TAG}}_enroll;

{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=79 WHERE singleton;
COMMIT;
