-- Version 67: recover administrator custody across active shared boundaries.
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
BEGIN
    PERFORM FROM wormhole_data.workspace_meta WHERE singleton AND workspace_id='{{WORKSPACE_ID}}'::uuid
        AND role_tag='{{TAG}}' AND schema_version=66 FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000'; END IF;
END
$guard$;

ALTER TABLE wormhole_data.workspace_admin_recovery ADD COLUMN boundary_recovery boolean NOT NULL DEFAULT false;

CREATE FUNCTION wormhole_data.admin_recovery_boundaries() RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $material$
DECLARE meta record; saved bytea; boundary record; enc record; sign record;
    profile jsonb; body jsonb; copies jsonb; boundaries jsonb:='[]'; count integer:=0;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<67 OR
       meta.state<>'ready' OR NOT meta.require_tls OR meta.tls_bundle IS NULL OR meta.tls_sequence<1 OR
       meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace recovery is unavailable' USING ERRCODE='WH002';
    END IF;
    profile:=convert_from(meta.signed_profile,'UTF8')::jsonb->'policy';
    IF NOT COALESCE(profile->>'profile' IN ('default','standard') AND profile->>'orgEscrow'='true',false)
        OR NOT wormhole_data.personal_import_boundaries_recoverable(meta.workspace_id) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT recovery_capsule INTO STRICT saved FROM wormhole_data.workspace_bootstrap WHERE singleton FOR SHARE NOWAIT;
    SELECT key_id,key_version,public_key INTO STRICT enc FROM wormhole_data.keys
        WHERE kind='org-enc' AND owner_id IS NULL AND status='active' AND suite=2 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    SELECT key_id,key_version,public_key INTO STRICT sign FROM wormhole_data.keys
        WHERE kind='org-sign' AND owner_id IS NULL AND status='active' AND suite=1 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    FOR boundary IN
        SELECT r.id,m.version,m.body,m.signer_key_id,m.signer_key_version FROM wormhole_data.boundaries r
        LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=r.id
        WHERE NOT r.deleted AND r.owner_user_id IS NULL ORDER BY r.id LIMIT 512 FOR SHARE OF r NOWAIT
    LOOP
        count:=count+1;
        IF count>511 OR (boundary.signer_key_id,boundary.signer_key_version) IS DISTINCT FROM (sign.key_id,sign.key_version)
            OR octet_length(boundary.body) NOT BETWEEN 1 AND 8192 THEN
            RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
        END IF;
        body:=convert_from(boundary.body,'UTF8')::jsonb;
        IF body->>'active' IS DISTINCT FROM 'true' OR body->>'orgEscrow' IS DISTINCT FROM 'true'
            OR body->>'previousView' IS NOT NULL OR body->>'previousSecret' IS NOT NULL THEN
            RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
        END IF;
        SELECT jsonb_agg(to_jsonb(item) ORDER BY item.kind) INTO copies FROM (
            SELECT k.key_id AS id,k.key_version AS version,k.kind,encode(c.enc,'base64') AS enc,
                encode(c.ciphertext,'base64') AS ciphertext,encode(c.signature,'base64') AS signature
            FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING(key_id,key_version)
            WHERE k.owner_id=boundary.id AND k.status='active' AND k.suite=2
                AND ((k.kind='boundary-secret' AND (k.key_id,k.key_version)=
                    ((body#>>'{secret,key,id}')::uuid,(body#>>'{secret,key,version}')::integer))
                     OR (k.kind='boundary-view' AND (k.key_id,k.key_version)=
                    ((body#>>'{view,key,id}')::uuid,(body#>>'{view,key,version}')::integer)))
                AND (c.holder_key_id,c.holder_key_version)=(enc.key_id,enc.key_version)
                AND (c.issuer_key_id,c.issuer_key_version)=(sign.key_id,sign.key_version)
                AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
            FOR SHARE OF k,c NOWAIT
        ) item;
        IF COALESCE(jsonb_array_length(copies),0)<>2 THEN
            RAISE EXCEPTION 'Workspace recovery copies are unavailable' USING ERRCODE='WH020';
        END IF;
        boundaries:=boundaries||jsonb_build_array(jsonb_build_object('boundaryId',boundary.id,'boundaryVersion',boundary.version,
            'boundary',encode(boundary.body,'base64'),'copies',copies));
    END LOOP;
    IF count=0 THEN RAISE EXCEPTION 'Workspace recovery graph is unavailable' USING ERRCODE='WH020'; END IF;
    RETURN jsonb_build_object('workspaceId',meta.workspace_id,'roleTag',meta.role_tag,'database',current_database(),
        'tlsDigest',encode(sha256(meta.tls_bundle),'hex'),'policy',encode(meta.signed_profile,'base64'),'capsule',encode(saved,'base64'),
        'organisationEncryption',jsonb_build_object('id',enc.key_id,'version',enc.key_version),
        'organisationSigning',jsonb_build_object('id',sign.key_id,'version',sign.key_version),
        'organisation',jsonb_build_object('encryption',encode(enc.public_key,'base64'),'signing',encode(sign.public_key,'base64')),
        'boundaries',boundaries);
END
$material$;

CREATE FUNCTION wormhole_data.require_boundary_recovery_deployer() RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $deployer$
BEGIN
    IF session_user<>'wh_{{TAG}}_deployer' OR NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) THEN
        RAISE EXCEPTION 'Workspace recovery requires its TLS deployer login' USING ERRCODE='42501';
    END IF;
END
$deployer$;

CREATE FUNCTION wormhole_api_v1.workspace_admin_recovery_boundaries() RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $read$
BEGIN
    PERFORM wormhole_data.require_boundary_recovery_deployer();
    RETURN wormhole_data.admin_recovery_boundaries()::text;
END
$read$;

-- The retirement guard continues to refuse envelopes and ordinary key writes.
-- Only an already reviewed recovery invitation can carry an existing root to
-- the new custodian. Its one-time login may rewrap that same source copy.
CREATE FUNCTION wormhole_data.recovery_invitation_root_copy(p wormhole_data.key_copies) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $allowed$
    SELECT EXISTS(
        SELECT FROM wormhole_data.group_boundary_rotation_queue q
        JOIN wormhole_data.boundary_grants g ON g.boundary_id=q.boundary_id AND g.permissions=31
        JOIN wormhole_data.invites i ON i.user_id=g.user_id
        JOIN wormhole_data.workspace_admin_recovery r ON r.invite_id=i.id AND r.boundary_recovery
        JOIN wormhole_data.keys holder ON (holder.key_id,holder.key_version)=(p.holder_key_id,p.holder_key_version)
            AND holder.owner_id=i.user_id AND holder.kind='user-enc'
        JOIN wormhole_data.keys issuer ON (issuer.key_id,issuer.key_version)=(p.issuer_key_id,p.issuer_key_version)
        WHERE (q.root_id,q.root_version)=(p.key_id,p.key_version) AND NOT EXISTS(
            SELECT FROM wormhole_data.group_boundary_rotation_queue x WHERE (x.root_id,x.root_version)=(p.holder_key_id,p.holder_key_version))
          AND i.kind='invite' AND i.used_at IS NULL AND i.expires_at>statement_timestamp()
          AND EXISTS(SELECT FROM jsonb_array_elements(convert_from(i.manifest,'UTF8')::jsonb->'copies') c
              WHERE c->'key'=jsonb_build_object('id',p.key_id,'version',p.key_version))
          AND ((session_user='wh_{{TAG}}_deployer' AND holder.status='pending'
                 AND (holder.key_id,holder.key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version)
                 AND issuer.kind='org-sign' AND issuer.status='active' AND issuer.owner_id IS NULL)
            OR (holder.status='active' AND issuer.kind='user-sign' AND issuer.status='active' AND issuer.owner_id=i.user_id
                AND EXISTS(SELECT FROM wormhole_data.invitation_logins l JOIN pg_roles pr ON pr.oid=l.role_oid AND pr.rolname=l.role_name
                    WHERE l.invite_id=i.id AND l.role_name=session_user AND NOT l.revoked AND pr.rolcanlogin)
                AND EXISTS(SELECT FROM wormhole_data.key_copies source WHERE (source.key_id,source.key_version)=(p.key_id,p.key_version)
                    AND (source.holder_key_id,source.holder_key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version))))
    )
$allowed$;

CREATE OR REPLACE FUNCTION wormhole_data.guard_pending_rotation_copy() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q
        WHERE (q.root_id,q.root_version) IN ((NEW.key_id,NEW.key_version),(NEW.holder_key_id,NEW.holder_key_version))) THEN
        IF TG_OP='INSERT' AND wormhole_data.recovery_invitation_root_copy(NEW) THEN RETURN NEW; END IF;
        RAISE EXCEPTION 'Boundary root is awaiting member rotation' USING ERRCODE='WH020';
    END IF;
    RETURN NEW;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.recover_workspace_boundaries(p jsonb,p_verifier text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $recover$
DECLARE proof jsonb; request_digest bytea; stored_digest bytea; invitation jsonb; manifest bytea; signed jsonb;
    actor uuid; issuance uuid; enc uuid; sign uuid; org_sign uuid; org_version integer;
    expires timestamptz; wrapped jsonb; copied uuid; copied_version integer; roots jsonb; expected jsonb;
BEGIN
    PERFORM wormhole_data.require_boundary_recovery_deployer();
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR octet_length(p::text)>1179648 OR p->>'version' IS DISTINCT FROM '2'
       OR jsonb_typeof(p->'copies') IS DISTINCT FROM 'array' OR p->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' THEN
        RAISE EXCEPTION 'Workspace recovery rejected' USING ERRCODE='WH002';
    END IF;
    PERFORM FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    invitation:=p->'invite';
    actor:=(invitation->>'userId')::uuid; issuance:=(invitation->>'inviteId')::uuid;
    request_digest:=sha256(convert_to(p::text,'UTF8'));
    SELECT r.request_digest INTO stored_digest FROM wormhole_data.workspace_admin_recovery r WHERE invite_id=issuance AND r.boundary_recovery;
    IF FOUND THEN
        IF stored_digest=request_digest THEN RETURN issuance; END IF;
        RAISE EXCEPTION 'Workspace recovery request changed' USING ERRCODE='WH002';
    END IF;
    proof:=wormhole_data.admin_recovery_boundaries();
    IF p->>'materialDigest' IS DISTINCT FROM encode(sha256(convert_to(proof::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'Workspace recovery state changed' USING ERRCODE='WH013';
    END IF;
    enc:=(p#>>'{encryption,key,id}')::uuid; sign:=(p#>>'{signing,key,id}')::uuid;
    org_sign:=(proof#>>'{organisationSigning,id}')::uuid; org_version:=(proof#>>'{organisationSigning,version}')::integer;
    expires:=to_timestamp((p->>'expiresAt')::bigint);
    manifest:=decode(p->>'manifest','base64'); signed:=convert_from(manifest,'UTF8')::jsonb;
    IF expires IS NULL OR expires<=clock_timestamp() OR expires>clock_timestamp()+interval '1 hour'
       OR invitation->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR invitation->>'keyId' IS DISTINCT FROM enc::text
       OR signed->>'formatVersion' IS DISTINCT FROM '1' OR signed->'context' IS DISTINCT FROM invitation
       OR jsonb_typeof(signed->'copies') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'Workspace recovery rejected' USING ERRCODE='WH002';
    END IF;
    SELECT jsonb_agg(jsonb_build_object('id',c->'id','version',c->'version')) INTO roots
    FROM jsonb_array_elements(proof->'boundaries') b CROSS JOIN LATERAL jsonb_array_elements(b->'copies') c;
    expected:=roots||jsonb_build_array(proof->'organisationEncryption',proof->'organisationSigning');
    IF jsonb_array_length(p->'copies')<>jsonb_array_length(expected) OR jsonb_array_length(signed->'copies')<>jsonb_array_length(expected)
       OR EXISTS(SELECT FROM jsonb_array_elements(expected) ref
            WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(signed->'copies') c WHERE c->'key'=ref
                AND c->'issuer'=proof->'organisationSigning' AND c->'holder'=jsonb_build_object('id',enc,'version',1))) THEN
        RAISE EXCEPTION 'Workspace recovery manifest does not match the reviewed roots' USING ERRCODE='WH002';
    END IF;
    PERFORM * FROM wormhole_data.parse_scram_verifier(p_verifier);
    INSERT INTO wormhole_data.users(id,login_name,is_admin) VALUES(actor,invitation->>'loginName',true);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES
        (enc,1,'user-enc',actor,2,'pending',decode(p#>>'{encryption,publicKey}','base64'),org_sign,org_version,1,decode(p#>>'{encryption,signature}','base64')),
        (sign,1,'user-sign',actor,1,'pending',decode(p#>>'{signing,publicKey}','base64'),org_sign,org_version,1,decode(p#>>'{signing,signature}','base64'));
    INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions)
    SELECT (b->>'boundaryId')::uuid,actor,31 FROM jsonb_array_elements(proof->'boundaries') b;
    INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state)
    VALUES(actor,1,decode(p->>'signedState','base64'));
    INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,
        bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision)
    VALUES(issuance,actor,'invite',sha256(convert_to(p_verifier,'UTF8')),actor,expires,enc,1,sign,1,
        decode(p->>'bootstrap','base64'),manifest,1);
    INSERT INTO wormhole_data.workspace_admin_recovery(invite_id,request_digest,boundary_recovery) VALUES(issuance,request_digest,true);
    FOR wrapped IN SELECT * FROM jsonb_array_elements(p->'copies') LOOP
        copied:=(wrapped->>'id')::uuid; copied_version:=(wrapped->>'version')::integer;
        IF NOT expected @> jsonb_build_array(jsonb_build_object('id',copied,'version',copied_version)) THEN
            RAISE EXCEPTION 'Workspace recovery keys changed' USING ERRCODE='WH013';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(copied,copied_version,enc,1,2,decode(wrapped->>'enc','base64'),decode(wrapped->>'ciphertext','base64'),
            org_sign,org_version,decode(wrapped->>'signature','base64'));
    END LOOP;
    PERFORM wormhole_data.provision_invitation_login(issuance,p_verifier);
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(actor,gen_random_uuid(),session_user,'ui','break_glass_recovery','invitation_published',inet_client_addr(),'recovery-v2');
    RETURN issuance;
END
$recover$;

REVOKE ALL ON FUNCTION wormhole_data.admin_recovery_boundaries(),wormhole_data.require_boundary_recovery_deployer(),
    wormhole_data.recovery_invitation_root_copy(wormhole_data.key_copies),
    wormhole_api_v1.workspace_admin_recovery_boundaries(),wormhole_api_v1.recover_workspace_boundaries(jsonb,text)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.workspace_admin_recovery_boundaries(),wormhole_api_v1.recover_workspace_boundaries(jsonb,text)
    TO wh_{{TAG}}_deployer;

{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=67 WHERE singleton;
COMMIT;
