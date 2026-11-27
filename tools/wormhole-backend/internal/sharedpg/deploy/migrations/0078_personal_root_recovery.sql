-- Version 78: restore both rotated personal roots to a freshly enrolled owner.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>77 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.restore_personal_roots(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_account uuid,p_suspension bigint,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,document text,sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,org_public bytea,org_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='20s' AS $restore_roots$
DECLARE actor record; subject record; manifest wormhole_data.boundary_manifests; boundary uuid;
    recipient wormhole_data.keys; org_signing record; org_encryption record; roots jsonb; expected text;
    old jsonb; item jsonb; root uuid; version integer; enc bytea; ciphertext bytea; proof bytea;
BEGIN
    IF p_account IS NULL OR p_account='00000000-0000-0000-0000-000000000000'::uuid
        OR p_suspension IS NULL OR p_suspension<1 OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'array'
            OR octet_length(p_publication::text)>4096)) THEN
        RAISE EXCEPTION 'Invalid personal root recovery request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    boundary:=wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,p_account);
    IF NOT wormhole_data.personal_account_rotation_available(actor.actor,p_account,boundary) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS(SELECT FROM wormhole_data.account_suspensions s JOIN wormhole_data.users u ON u.id=s.account_id
        WHERE s.account_id=p_account AND s.revision=p_suspension AND u.disabled FOR SHARE OF u,s NOWAIT) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT m.* INTO manifest FROM wormhole_data.boundaries b JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        WHERE b.id=boundary AND b.owner_user_id=p_account AND NOT b.deleted FOR SHARE OF b,m NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    old:=convert_from(manifest.body,'UTF8')::jsonb;
    IF old->>'active' IS DISTINCT FROM 'true' OR old->>'orgEscrow' IS DISTINCT FROM 'true'
        OR old->>'previousView' IS NOT NULL OR old->>'previousSecret' IS NOT NULL
        OR NOT EXISTS(SELECT FROM wormhole_data.keys k WHERE k.kind='org-sign' AND k.owner_id IS NULL AND k.status='active'
            AND (k.key_id,k.key_version)=(manifest.signer_key_id,manifest.signer_key_version)) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF 2<>(SELECT count(*) FROM wormhole_data.account_suspension_roots r JOIN wormhole_data.keys k
        ON (k.key_id,k.key_version)=(r.root_id,r.root_version) WHERE r.account_id=p_account AND r.boundary_id=boundary AND k.status='retired') THEN
        status:='rotation-required'; RETURN NEXT; RETURN;
    END IF;
    SELECT e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version,e.certificate,state.signed_state,
        p.encryption_key_id AS previous_encryption,p.encryption_key_version AS previous_version,
        p.signing_key_id AS previous_signing,p.signing_key_version AS previous_signing_version,
        p.state_sequence AS previous_sequence,history.certificate AS previous_certificate
    INTO subject FROM wormhole_data.account_suspension_enrollments p
    JOIN wormhole_data.user_enrollment_history history ON history.user_id=p.account_id
        AND (history.signing_key_id,history.signing_key_version)=(p.signing_key_id,p.signing_key_version)
    JOIN wormhole_data.user_enrollments e ON e.user_id=p.account_id
    JOIN wormhole_data.user_key_states state ON state.user_id=p.account_id AND state.state_sequence>p.state_sequence
    JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(e.encryption_key_id,e.encryption_key_version)
    JOIN wormhole_data.keys sig ON (sig.key_id,sig.key_version)=(e.signing_key_id,e.signing_key_version)
    WHERE p.account_id=p_account AND e.encryption_key_id<>p.encryption_key_id AND e.signing_key_id<>p.signing_key_id
        AND h.kind='user-enc' AND h.owner_id=p_account AND h.status='active'
        AND sig.kind='user-sign' AND sig.owner_id=p_account AND sig.status='active'
        AND convert_from(state.signed_state,'UTF8')::jsonb->>'active'='true'
    FOR SHARE OF p,e,state,h,sig NOWAIT;
    IF NOT FOUND THEN status:='enrollment-required'; RETURN NEXT; RETURN; END IF;
    IF NOT wormhole_data.personal_account_recovery_required(p_account) THEN
        status:='unchanged'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active'
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(manifest.signer_key_id,manifest.signer_key_version)
        AND k.cert_revision=1 FOR SHARE NOWAIT;
    SELECT jsonb_agg(body ORDER BY purpose) INTO roots FROM (
        SELECT r.purpose,jsonb_build_object('id',k.key_id,'version',k.key_version,'enc',encode(c.enc,'base64'),
            'ciphertext',encode(c.ciphertext,'base64'),'signature',encode(c.signature,'base64')) AS body
        FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.keys k ON k.key_id=r.root_id AND k.key_version>r.root_version AND k.status='active'
            AND k.owner_id=boundary AND k.kind=CASE r.purpose WHEN 1 THEN 'boundary-view' ELSE 'boundary-secret' END
        JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(k.key_id,k.key_version)
        WHERE r.account_id=p_account AND r.boundary_id=boundary
            AND old#>ARRAY[CASE r.purpose WHEN 1 THEN 'view' ELSE 'secret' END,'key']=jsonb_build_object('id',k.key_id,'version',k.key_version)
            AND (c.holder_key_id,c.holder_key_version)=(recipient.key_id,recipient.key_version)
            AND (c.issuer_key_id,c.issuer_key_version)=(manifest.signer_key_id,manifest.signer_key_version)
            AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
        FOR SHARE OF k,c NOWAIT
    ) current_roots;
    IF jsonb_array_length(roots) IS DISTINCT FROM 2 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    expected:=jsonb_build_object('accountId',p_account,'suspension',p_suspension::text,'manifest',encode(manifest.body,'base64'),
        'roster',jsonb_build_array(jsonb_build_array(p_account::text,subject.encryption_key_id::text,subject.encryption_key_version::text,
            encode(subject.signed_state,'hex'),encode(subject.certificate,'hex'))),
        'previousCertificate',encode(subject.previous_certificate,'base64'),'previousSequence',subject.previous_sequence::text,
        'previousEncryption',jsonb_build_object('id',subject.previous_encryption,'version',subject.previous_version),
        'previousSigning',jsonb_build_object('id',subject.previous_signing,'version',subject.previous_signing_version),
        'signing',jsonb_build_object('id',subject.signing_key_id,'version',subject.signing_key_version),
        'recovery',jsonb_build_object('id',recipient.key_id,'version',recipient.key_version),'roots',roots)::text;
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/personal-root-recovery:'||expected,'UTF8')) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; document:=expected; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    IF (org_signing.org_key_id,org_signing.org_key_version)<>(manifest.signer_key_id,manifest.signer_key_version)
        OR (org_encryption.org_key_id,org_encryption.org_key_version)<>(recipient.key_id,recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; document:=expected;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version; org_enc:=org_encryption.enc;
        org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'personal_root_recovery_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    IF jsonb_array_length(p_publication)<>2 OR EXISTS(SELECT FROM jsonb_array_elements(roots) r
        WHERE 1<>(SELECT count(*) FROM jsonb_array_elements(p_publication) c WHERE (c->>'id',c->>'version')=(r->>'id',r->>'version'))) THEN
        RAISE EXCEPTION 'Incomplete personal root recovery publication' USING ERRCODE='22023';
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(p_publication) LOOP
        root:=(item->>'id')::uuid; version:=(item->>'version')::integer;
        enc:=decode(item->>'enc','base64'); ciphertext:=decode(item->>'ciphertext','base64'); proof:=decode(item->>'signature','base64');
        IF octet_length(enc) IS DISTINCT FROM 32 OR octet_length(ciphertext) IS DISTINCT FROM 48 OR octet_length(proof) IS DISTINCT FROM 64 THEN
            RAISE EXCEPTION 'Invalid personal root recovery copy' USING ERRCODE='22023';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(root,version,subject.encryption_key_id,subject.encryption_key_version,2,enc,ciphertext,manifest.signer_key_id,manifest.signer_key_version,proof)
        ON CONFLICT (key_id,key_version,holder_key_id,holder_key_version) DO UPDATE SET
            suite=excluded.suite,enc=excluded.enc,ciphertext=excluded.ciphertext,issuer_key_id=excluded.issuer_key_id,
            issuer_key_version=excluded.issuer_key_version,signature=excluded.signature;
    END LOOP;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,admin_boundary_id,access_account_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','personal_root_recovery','success',inet_client_addr(),actor.app_version,boundary,p_account);
    status:='changed'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::text,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea;
END
$restore_roots$;

REVOKE ALL ON FUNCTION wormhole_api_v1.restore_personal_roots(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.restore_personal_roots(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea,jsonb)
    TO wh_{{TAG}}_user;
{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=78 WHERE singleton;
COMMIT;
