-- Version 48: scoped recovery of an administrator through certified enrollment.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>47 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.workspace_admin_recovery (
    invite_id uuid PRIMARY KEY REFERENCES wormhole_data.invites(id),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32)
);

CREATE FUNCTION wormhole_data.admin_recovery_material() RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE meta record; saved record; b record; enc record; sign record; copies jsonb; body jsonb; profile jsonb;
BEGIN
    IF session_user<>'wh_{{TAG}}_deployer' OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) THEN
        RAISE EXCEPTION 'Workspace recovery requires its TLS deployer login' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>48 OR
       meta.state<>'ready' OR NOT meta.require_tls OR meta.tls_bundle IS NULL OR meta.tls_sequence<1 OR
       meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace recovery is unavailable' USING ERRCODE='WH002';
    END IF;
    profile:=pg_catalog.convert_from(meta.signed_profile,'UTF8')::jsonb->'policy';
    IF NOT COALESCE(profile->>'profile' IN ('default','standard') AND profile->>'orgEscrow'='true',false) THEN
        RAISE EXCEPTION 'Workspace recovery profile is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT recovery_capsule INTO STRICT saved FROM wormhole_data.workspace_bootstrap WHERE singleton FOR SHARE NOWAIT;
    -- F2 has one workspace boundary. Do not issue a partially equipped admin
    -- for a workspace whose recovery needs a larger permission graph.
    SELECT m.boundary_id,m.version,m.body INTO STRICT b
    FROM wormhole_data.boundaries r JOIN wormhole_data.boundary_manifests m ON m.boundary_id=r.id
    WHERE NOT r.deleted AND r.owner_user_id IS NULL FOR SHARE OF r,m NOWAIT;
    IF EXISTS(SELECT FROM wormhole_data.boundaries r WHERE NOT r.deleted AND r.id<>b.boundary_id) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT key_id,key_version,public_key INTO STRICT enc FROM wormhole_data.keys
    WHERE kind='org-enc' AND owner_id IS NULL AND status='active' AND suite=2 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    SELECT key_id,key_version,public_key INTO STRICT sign FROM wormhole_data.keys
    WHERE kind='org-sign' AND owner_id IS NULL AND status='active' AND suite=1 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    body:=pg_catalog.convert_from(b.body,'UTF8')::jsonb;
    IF NOT COALESCE(body->>'active'='true' AND body->>'orgEscrow'='true' AND
        body->'previousView'='null'::jsonb AND body->'previousSecret'='null'::jsonb,false) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT pg_catalog.jsonb_agg(item.copy ORDER BY item.kind) INTO copies
    FROM (
        SELECT k.kind,pg_catalog.jsonb_build_object(
            'id',k.key_id,'version',k.key_version,'kind',k.kind,
            'enc',pg_catalog.encode(c.enc,'base64'),'ciphertext',pg_catalog.encode(c.ciphertext,'base64'),
            'signature',pg_catalog.encode(c.signature,'base64')) AS copy
        FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING (key_id,key_version)
        WHERE k.owner_id=b.boundary_id AND k.status='active' AND
            ((k.kind='boundary-secret' AND (k.key_id,k.key_version)=
                ((body#>>'{secret,key,id}')::uuid,(body#>>'{secret,key,version}')::integer))
             OR (k.kind='boundary-view' AND (k.key_id,k.key_version)=
                ((body#>>'{view,key,id}')::uuid,(body#>>'{view,key,version}')::integer)))
            AND (c.holder_key_id,c.holder_key_version)=(enc.key_id,enc.key_version)
            AND (c.issuer_key_id,c.issuer_key_version)=(sign.key_id,sign.key_version)
            AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
        FOR SHARE OF k,c NOWAIT
    ) item;
    IF COALESCE(pg_catalog.jsonb_array_length(copies),0)<>2 THEN
        RAISE EXCEPTION 'Workspace recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'workspaceId',meta.workspace_id,'roleTag',meta.role_tag,'database',pg_catalog.current_database(),
        'tlsDigest',pg_catalog.encode(pg_catalog.sha256(meta.tls_bundle),'hex'),
        'policy',pg_catalog.encode(meta.signed_profile,'base64'),
        'capsule',pg_catalog.encode(saved.recovery_capsule,'base64'),
        'organisationEncryption',pg_catalog.jsonb_build_object('id',enc.key_id,'version',enc.key_version),
        'organisationSigning',pg_catalog.jsonb_build_object('id',sign.key_id,'version',sign.key_version),
        'organisation',pg_catalog.jsonb_build_object('encryption',pg_catalog.encode(enc.public_key,'base64'),
            'signing',pg_catalog.encode(sign.public_key,'base64')),
        'boundaryId',b.boundary_id,'boundary',pg_catalog.encode(b.body,'base64'),'boundaryVersion',b.version,
        'copies',copies);
END
$material$;

CREATE FUNCTION wormhole_api_v1.workspace_admin_recovery_material() RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
RETURN wormhole_data.admin_recovery_material()::text;

CREATE FUNCTION wormhole_api_v1.recover_workspace_admin(p jsonb,p_verifier text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $recover$
DECLARE proof jsonb; request_digest bytea; stored_digest bytea; invitation jsonb;
    actor uuid; issuance uuid; enc uuid; sign uuid; org_sign uuid; org_version integer;
    expires timestamptz; wrapped jsonb; copied uuid; copied_version integer;
BEGIN
    IF p IS NULL OR pg_catalog.jsonb_typeof(p)<>'object' OR octet_length(p::text)>131072 OR
       p->>'version' IS DISTINCT FROM '1' OR pg_catalog.jsonb_typeof(p->'copies') IS DISTINCT FROM 'array' OR
       p->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' THEN
        RAISE EXCEPTION 'Workspace recovery rejected' USING ERRCODE='WH002';
    END IF;
    IF pg_catalog.jsonb_array_length(p->'copies')<>4 THEN
        RAISE EXCEPTION 'Workspace recovery rejected' USING ERRCODE='WH002';
    END IF;
    -- Serialize publication and observe the ready workspace under the same
    -- workspace lock used for policy, TLS and catalog changes.
    PERFORM 1 FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    proof:=wormhole_data.admin_recovery_material();
    invitation:=p->'invite';
    actor:=(invitation->>'userId')::uuid; issuance:=(invitation->>'inviteId')::uuid;
    request_digest:=pg_catalog.sha256(pg_catalog.convert_to(p::text,'UTF8'));
    SELECT r.request_digest INTO stored_digest FROM wormhole_data.workspace_admin_recovery r WHERE invite_id=issuance;
    IF FOUND THEN
        IF stored_digest=request_digest THEN RETURN issuance; END IF;
        RAISE EXCEPTION 'Workspace recovery request changed' USING ERRCODE='WH002';
    END IF;
    IF p->>'materialDigest' IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(proof::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'Workspace recovery state changed' USING ERRCODE='WH013';
    END IF;
    enc:=(p#>>'{encryption,key,id}')::uuid; sign:=(p#>>'{signing,key,id}')::uuid;
    org_sign:=(proof#>>'{organisationSigning,id}')::uuid; org_version:=(proof#>>'{organisationSigning,version}')::integer;
    expires:=pg_catalog.to_timestamp((p->>'expiresAt')::bigint);
    IF expires IS NULL OR expires<=pg_catalog.clock_timestamp() OR expires>pg_catalog.clock_timestamp()+interval '1 hour' OR
       invitation->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR
       invitation->>'keyId' IS DISTINCT FROM enc::text THEN
        RAISE EXCEPTION 'Workspace recovery rejected' USING ERRCODE='WH002';
    END IF;
    PERFORM * FROM wormhole_data.parse_scram_verifier(p_verifier);
    INSERT INTO wormhole_data.users(id,login_name,is_admin) VALUES(actor,invitation->>'loginName',true);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES
        (enc,1,'user-enc',actor,2,'pending',pg_catalog.decode(p#>>'{encryption,publicKey}','base64'),org_sign,org_version,1,pg_catalog.decode(p#>>'{encryption,signature}','base64')),
        (sign,1,'user-sign',actor,1,'pending',pg_catalog.decode(p#>>'{signing,publicKey}','base64'),org_sign,org_version,1,pg_catalog.decode(p#>>'{signing,signature}','base64'));
    FOR wrapped IN SELECT * FROM pg_catalog.jsonb_array_elements(p->'copies') LOOP
        copied:=(wrapped->>'id')::uuid; copied_version:=(wrapped->>'version')::integer;
        IF NOT EXISTS (
            SELECT FROM pg_catalog.jsonb_array_elements(proof->'copies') expected
            WHERE expected->>'id'=copied::text AND expected->>'version'=copied_version::text
            UNION ALL
            SELECT FROM (VALUES (proof->'organisationEncryption'),(proof->'organisationSigning')) AS org(expected)
            WHERE expected->>'id'=copied::text AND expected->>'version'=copied_version::text
        ) THEN
            RAISE EXCEPTION 'Workspace recovery keys changed' USING ERRCODE='WH013';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(copied,copied_version,enc,1,2,pg_catalog.decode(wrapped->>'enc','base64'),pg_catalog.decode(wrapped->>'ciphertext','base64'),
            org_sign,org_version,pg_catalog.decode(wrapped->>'signature','base64'));
    END LOOP;
    INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES((proof->>'boundaryId')::uuid,actor,31);
    INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state)
    VALUES(actor,1,pg_catalog.decode(p->>'signedState','base64'));
    INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,
        bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision)
    VALUES(issuance,actor,'invite',pg_catalog.sha256(pg_catalog.convert_to(p_verifier,'UTF8')),actor,expires,enc,1,sign,1,
        pg_catalog.decode(p->>'bootstrap','base64'),pg_catalog.decode(p->>'manifest','base64'),1);
    PERFORM wormhole_data.provision_invitation_login(issuance,p_verifier);
    INSERT INTO wormhole_data.workspace_admin_recovery VALUES(issuance,request_digest);
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(actor,pg_catalog.gen_random_uuid(),session_user,'ui','break_glass_recovery','invitation_published',pg_catalog.inet_client_addr(),'recovery-v1');
    RETURN issuance;
END
$recover$;

REVOKE ALL ON TABLE wormhole_data.workspace_admin_recovery FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.admin_recovery_material(),
    wormhole_api_v1.workspace_admin_recovery_material(),wormhole_api_v1.recover_workspace_admin(jsonb,text)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT USAGE ON SCHEMA wormhole_api_v1 TO wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.workspace_admin_recovery_material(),wormhole_api_v1.recover_workspace_admin(jsonb,text)
    TO wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=48 WHERE singleton;
COMMIT;
