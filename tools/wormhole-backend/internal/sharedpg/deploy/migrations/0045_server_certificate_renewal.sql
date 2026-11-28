-- Version 45: audited access to the wrapped server CA for certificate renewal.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>44 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Keep bootstrap available on fresh and still-provisioning workspaces. The
-- bootstrap format is versioned separately from subsequent schema migrations.
CREATE OR REPLACE FUNCTION wormhole_api_v1.bootstrap_workspace(p jsonb,p_verifier text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $bootstrap$
DECLARE meta record; receipt record; request_digest bytea; invite jsonb; actor uuid; issuance uuid;
        enc uuid; sign uuid; org_enc uuid; org_sign uuid; view_key uuid; secret_key uuid; boundary uuid;
        expires timestamptz; wrapped jsonb; holder uuid; copied uuid;
BEGIN
    IF NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false)
       OR p IS NULL OR pg_catalog.jsonb_typeof(p)<>'object' OR octet_length(p::text)>262144
       OR p->>'version' IS DISTINCT FROM '1' OR p->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR p->>'roleTag' IS DISTINCT FROM '{{TAG}}'
       OR p->>'database' IS DISTINCT FROM pg_catalog.current_database() THEN
        RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT meta.require_tls OR meta.schema_version<45 OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' THEN
        RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
    END IF;
    request_digest:=pg_catalog.sha256(pg_catalog.convert_to(p::text,'UTF8'));
    SELECT * INTO receipt FROM wormhole_data.workspace_bootstrap WHERE singleton;
    IF FOUND THEN
        IF receipt.request_digest=request_digest THEN RETURN meta.state; END IF;
        RAISE EXCEPTION 'Workspace bootstrap already exists' USING ERRCODE='WH002';
    END IF;
    IF meta.state<>'provisioning' OR meta.signed_profile IS NOT NULL OR EXISTS(SELECT FROM wormhole_data.users)
       OR EXISTS(SELECT FROM wormhole_data.keys) OR EXISTS(SELECT FROM wormhole_data.boundaries)
       OR pg_catalog.jsonb_typeof(p->'copies') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
    END IF;
    IF pg_catalog.jsonb_array_length(p->'copies')<>6 THEN
        RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
    END IF;
    invite:=p->'invite';
    actor:=(invite->>'userId')::uuid; issuance:=(invite->>'inviteId')::uuid;
    enc:=(p->'encryption'->'key'->>'id')::uuid; sign:=(p->'signing'->'key'->>'id')::uuid;
    org_enc:=(p->'organisationEncryption'->>'id')::uuid; org_sign:=(p->'organisationSigning'->>'id')::uuid;
    view_key:=(p->'boundary'->'view'->'key'->>'id')::uuid; secret_key:=(p->'boundary'->'secret'->'key'->>'id')::uuid;
    boundary:=(p->'boundary'->>'boundaryId')::uuid;
    expires:=pg_catalog.to_timestamp((p->>'expiresAt')::bigint);
    IF expires IS NULL OR expires<=pg_catalog.clock_timestamp() OR expires>pg_catalog.clock_timestamp()+interval '73 hours' THEN
        RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
    END IF;
    INSERT INTO wormhole_data.users(id,login_name,is_admin) VALUES(actor,invite->>'loginName',true);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key) VALUES
        (org_enc,1,'org-enc',NULL,2,pg_catalog.decode(p->'organisation'->>'encryption','base64')),
        (org_sign,1,'org-sign',NULL,1,pg_catalog.decode(p->'organisation'->>'signing','base64')),
        (view_key,1,'boundary-view',boundary,2,pg_catalog.decode(p->'boundary'->'view'->>'public','base64')),
        (secret_key,1,'boundary-secret',boundary,2,pg_catalog.decode(p->'boundary'->'secret'->>'public','base64'));
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES
        (enc,1,'user-enc',actor,2,'pending',pg_catalog.decode(p->'encryption'->>'publicKey','base64'),org_sign,1,1,pg_catalog.decode(p->'encryption'->>'signature','base64')),
        (sign,1,'user-sign',actor,1,'pending',pg_catalog.decode(p->'signing'->>'publicKey','base64'),org_sign,1,1,pg_catalog.decode(p->'signing'->>'signature','base64'));
    FOR wrapped IN SELECT * FROM pg_catalog.jsonb_array_elements(p->'copies') LOOP
        holder:=(wrapped->>'holder')::uuid; copied:=(wrapped->>'key')::uuid;
        IF NOT COALESCE((holder=enc AND copied IN(org_enc,org_sign,view_key,secret_key))
            OR (holder=org_enc AND copied IN(view_key,secret_key)),false) THEN
            RAISE EXCEPTION 'Workspace bootstrap rejected' USING ERRCODE='WH002';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(copied,1,holder,1,2,pg_catalog.decode(wrapped->>'enc','base64'),pg_catalog.decode(wrapped->>'ciphertext','base64'),org_sign,1,pg_catalog.decode(wrapped->>'signature','base64'));
    END LOOP;
    INSERT INTO wormhole_data.boundaries(id) VALUES(boundary);
    INSERT INTO wormhole_data.boundary_manifests(boundary_id,body,signer_key_id,signer_key_version,signature)
    VALUES(boundary,pg_catalog.decode(p->>'boundaryBody','base64'),org_sign,1,pg_catalog.decode(p->'boundary'->>'signature','base64'));
    INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES(boundary,actor,31);
    INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state)
    VALUES(actor,1,pg_catalog.decode(p->>'signedState','base64'));
    INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision)
    VALUES(issuance,actor,'invite',pg_catalog.sha256(pg_catalog.convert_to(p_verifier,'UTF8')),actor,expires,enc,1,sign,1,
        pg_catalog.decode(p->>'bootstrap','base64'),pg_catalog.decode(p->>'manifest','base64'),1);
    PERFORM wormhole_data.provision_invitation_login(issuance,p_verifier);
    UPDATE wormhole_data.workspace_meta SET signed_profile=pg_catalog.decode(p->>'signedProfile','base64'),
        tls_sequence=1,tls_bundle=pg_catalog.decode(p->>'tlsBundle','base64') WHERE singleton;
    INSERT INTO wormhole_data.workspace_bootstrap(invite_id,request_digest,recovery_capsule)
    VALUES(issuance,request_digest,pg_catalog.decode(p->>'recovery','base64'));
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(actor,pg_catalog.gen_random_uuid(),session_user,'ui','bootstrap_workspace','success',pg_catalog.inet_client_addr(),'bootstrap-v1');
    RETURN 'provisioning';
END
$bootstrap$;

CREATE FUNCTION wormhole_api_v1.server_certificate_renewal(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,ca jsonb)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $renewal$
DECLARE identity record; meta record; copy record; capsule jsonb; admitted record; account jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.is_admin AND NOT u.disabled) THEN
        RAISE EXCEPTION 'Workspace administrator required' USING ERRCODE='WH020';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR NOT meta.require_tls OR NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false)
       OR meta.tls_sequence<1 OR meta.tls_sequence IS DISTINCT FROM p_tls_sequence
       OR pg_catalog.sha256(meta.tls_bundle) IS DISTINCT FROM p_tls_digest
       OR pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM p_profile_digest THEN
        RAISE EXCEPTION 'Workspace TLS state changed' USING ERRCODE='WH011';
    END IF;
    IF COALESCE(pg_catalog.convert_from(meta.signed_profile,'UTF8')::jsonb #>> '{policy,profile}','')
        NOT IN ('default','standard') THEN
        RAISE EXCEPTION 'Workspace profile does not authorize ordinary CA renewal' USING ERRCODE='WH020';
    END IF;
    SELECT pg_catalog.convert_from(a.signed_state,'UTF8')::jsonb INTO account
    FROM wormhole_data.user_key_states a WHERE a.user_id=identity.user_id
        AND pg_catalog.sha256(a.signed_state)=p_account_digest FOR SHARE NOWAIT;
    IF NOT FOUND OR account->>'active' IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'Workspace account state changed' USING ERRCODE='WH010';
    END IF;
    PERFORM 1 FROM wormhole_data.user_enrollments e WHERE e.user_id=identity.user_id
        AND (e.encryption_key_id,e.encryption_key_version)=(p_holder,p_holder_version)
        AND (e.signing_key_id,e.signing_key_version)=(p_signer,p_signer_version) FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace account state changed' USING ERRCODE='WH010';
    END IF;
    SELECT pg_catalog.convert_from(b.recovery_capsule,'UTF8')::jsonb INTO capsule
    FROM wormhole_data.workspace_bootstrap b WHERE b.singleton;
    IF capsule->>'version' IS DISTINCT FROM '2' OR pg_catalog.jsonb_typeof(capsule->'ca') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'Workspace issuing CA unavailable' USING ERRCODE='WH020';
    END IF;
    SELECT k.key_id,k.key_version,c.enc,c.ciphertext,c.signature INTO copy
    FROM wormhole_data.key_copies c
    JOIN wormhole_data.keys k USING (key_id,key_version)
    JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
    JOIN wormhole_data.keys s ON (s.key_id,s.key_version)=(c.issuer_key_id,c.issuer_key_version)
    WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active'
      AND h.kind='user-enc' AND h.owner_id=identity.user_id AND h.status='active'
      AND s.kind='user-sign' AND s.owner_id=identity.user_id AND s.status='active'
      AND (h.key_id,h.key_version)=(p_holder,p_holder_version)
      AND (s.key_id,s.key_version)=(p_signer,p_signer_version)
      AND c.suite=2 AND pg_catalog.octet_length(c.enc)=32 AND pg_catalog.octet_length(c.ciphertext)=48
    FOR SHARE OF k,h,s,c NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace administrator key copy unavailable' USING ERRCODE='WH020';
    END IF;
    SELECT s.id,s.app_version INTO STRICT admitted
    FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
    WHERE a.device_id=identity.device_id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(identity.user_id,admitted.id,session_user,'ui','server_certificate_renewal','key_copy_released',
        pg_catalog.inet_client_addr(),admitted.app_version);
    RETURN QUERY SELECT copy.key_id,copy.key_version,copy.enc,copy.ciphertext,copy.signature,capsule->'ca';
END
$renewal$;

REVOKE ALL ON FUNCTION wormhole_api_v1.server_certificate_renewal(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.server_certificate_renewal(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=45 WHERE singleton;
COMMIT;
