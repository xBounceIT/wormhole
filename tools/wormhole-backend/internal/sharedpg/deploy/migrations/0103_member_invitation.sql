-- Version 103: initial enrollment for an ordinary member without group grants.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
BEGIN
    PERFORM FROM wormhole_data.workspace_meta WHERE singleton AND workspace_id='{{WORKSPACE_ID}}'::uuid
        AND role_tag='{{TAG}}' AND schema_version=102 FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000'; END IF;
END
$guard$;

ALTER TABLE wormhole_data.invites ADD COLUMN member_request_digest bytea CHECK(octet_length(member_request_digest)=32);

CREATE FUNCTION wormhole_api_v1.member_invitation_signer(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_login text)
RETURNS TABLE(role_tag text,database_name text,key_id uuid,key_version integer,enc bytea,ciphertext bytea,proof bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE actor record;
BEGIN
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    IF NOT FOUND OR NOT actor.custodian OR p_login IS NULL OR octet_length(p_login) NOT BETWEEN 1 AND 256 OR p_login~'[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Member invitation unavailable' USING ERRCODE='WH020';
    END IF;
    IF EXISTS(SELECT FROM wormhole_data.users WHERE login_name=p_login) THEN RETURN; END IF;
    RETURN QUERY SELECT '{{TAG}}'::text,current_database()::text,c.key_id,c.key_version,c.enc,c.ciphertext,c.signature
        FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(actor.organisation_signer,actor.organisation_version)
        AND (c.holder_key_id,c.holder_key_version)=(p_holder,p_holder_version)
        AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version) AND c.suite=2 FOR SHARE NOWAIT;
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'member_invitation_material','signer_copy_released');
END
$material$;

CREATE FUNCTION wormhole_api_v1.publish_member_invitation(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p jsonb,p_verifier text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC'
AS $publish$
DECLARE actor record; prior record; invite jsonb; subject uuid; issuance uuid; login text; expiry timestamptz;
    enc_cert jsonb; sign_cert jsonb; enc_key uuid; sign_key uuid; cert jsonb; manifest bytea; body jsonb;
    state bytea; state_json jsonb; digest bytea; verifier_hash bytea; authority jsonb;
BEGIN
    IF NOT coalesce(wormhole_api_v1.account_reset_publication_ready(),false) THEN
        RAISE EXCEPTION 'Member invitation publication logging is enabled' USING ERRCODE='WH024';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,true);
    IF NOT FOUND OR NOT actor.custodian THEN RAISE EXCEPTION 'Member invitation unavailable' USING ERRCODE='WH020'; END IF;
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR octet_length(p::text)>65536 OR p_verifier IS NULL
        OR jsonb_typeof(p->'name') IS DISTINCT FROM 'string' OR octet_length(p->>'name')>4096 OR p->>'name'~'[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Invalid member invitation' USING ERRCODE='22023';
    END IF;
    PERFORM FROM wormhole_data.parse_scram_verifier(p_verifier);
    invite:=p->'context'; subject:=(invite->>'userId')::uuid; issuance:=(invite->>'inviteId')::uuid; login:=invite->>'loginName';
    expiry:=to_timestamp((p->>'expiresAt')::bigint);
    IF invite->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR login IS NULL OR octet_length(login) NOT BETWEEN 1 AND 256
        OR login~'[[:cntrl:]]' OR login IS DISTINCT FROM normalize(lower(login),NFC)
        OR expiry IS NULL OR expiry<=clock_timestamp() OR expiry>clock_timestamp()+interval '72 hours' THEN
        RAISE EXCEPTION 'Invalid member invitation' USING ERRCODE='22023';
    END IF;
    digest:=sha256(convert_to(p::text,'UTF8')); verifier_hash:=sha256(convert_to(p_verifier,'UTF8'));
    SELECT i.*,l.revoked INTO prior FROM wormhole_data.invites i JOIN wormhole_data.invitation_logins l ON l.invite_id=i.id
        WHERE i.id=issuance FOR SHARE OF i,l NOWAIT;
    IF FOUND THEN
        IF prior.member_request_digest=digest AND prior.code_hash=verifier_hash AND prior.created_by=actor.actor
            AND prior.used_at IS NULL AND prior.attempts<5 AND NOT prior.revoked
            AND EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=prior.user_id AND NOT u.disabled AND NOT u.is_admin)
        THEN RETURN 'published'; END IF;
        RAISE EXCEPTION 'Member invitation changed' USING ERRCODE='WH010';
    END IF;
    enc_cert:=p->'encryption'; sign_cert:=p->'signing';
    enc_key:=(enc_cert#>>'{key,id}')::uuid; sign_key:=(sign_cert#>>'{key,id}')::uuid;
    authority:=jsonb_build_object('id',actor.organisation_signer,'version',actor.organisation_version);
    manifest:=decode(p->>'manifest','base64'); body:=convert_from(manifest,'UTF8')::jsonb;
    state:=decode(p->>'signedState','base64'); state_json:=convert_from(state,'UTF8')::jsonb;
    IF enc_key IS NULL OR sign_key IS NULL OR enc_key=sign_key OR invite->>'keyId' IS DISTINCT FROM enc_key::text
        OR invite->>'keyVersion' IS DISTINCT FROM '1' OR body->'context' IS DISTINCT FROM invite
        OR body->>'expiresAt' IS DISTINCT FROM p->>'expiresAt' OR body->>'formatVersion' IS DISTINCT FROM '1'
        OR body->>'revision' IS DISTINCT FROM '1' OR body->'copies' IS DISTINCT FROM '[]'::jsonb OR body->'issuers' IS DISTINCT FROM '[]'::jsonb
        OR enc_cert->>'kind' IS DISTINCT FROM 'user-enc' OR sign_cert->>'kind' IS DISTINCT FROM 'user-sign'
        OR body#>>'{bootstrap,encryption}' IS DISTINCT FROM enc_cert->>'publicKey'
        OR body#>>'{bootstrap,signing}' IS DISTINCT FROM sign_cert->>'publicKey'
        OR state_json->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR state_json->>'userId' IS DISTINCT FROM subject::text
        OR state_json->>'sequence' IS DISTINCT FROM '1' OR state_json->>'active' IS DISTINCT FROM 'true'
        OR state_json->'encryption' IS DISTINCT FROM enc_cert->'key' OR state_json->'signing' IS DISTINCT FROM sign_cert->'key'
        OR state_json->'signer' IS DISTINCT FROM authority THEN
        RAISE EXCEPTION 'Invalid member certification' USING ERRCODE='22023';
    END IF;
    INSERT INTO wormhole_data.users(id,login_name,name,is_admin) VALUES(subject,login,nullif(p->>'name',''),false)
        ON CONFLICT (login_name) DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Member login already exists' USING ERRCODE='WH010';
    END IF;
    FOR cert IN SELECT * FROM jsonb_array_elements(jsonb_build_array(enc_cert,sign_cert)) LOOP
        IF cert->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR cert->>'userId' IS DISTINCT FROM subject::text
            OR cert#>>'{key,version}' IS DISTINCT FROM '1' OR cert->>'revision' IS DISTINCT FROM '1'
            OR cert->'signer' IS DISTINCT FROM authority OR octet_length(decode(cert->>'publicKey','base64')) IS DISTINCT FROM 32
            OR octet_length(decode(cert->>'signature','base64')) IS DISTINCT FROM 64 THEN
            RAISE EXCEPTION 'Invalid member certificate' USING ERRCODE='22023';
        END IF;
        INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status,public_key,
            cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature)
        VALUES((cert#>>'{key,id}')::uuid,1,cert->>'kind',subject,CASE WHEN cert->>'kind'='user-enc' THEN 2 ELSE 1 END,
            'pending',decode(cert->>'publicKey','base64'),actor.organisation_signer,actor.organisation_version,1,decode(cert->>'signature','base64'));
    END LOOP;
    INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES(subject,1,state);
    INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,
        bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision,member_request_digest)
    VALUES(issuance,subject,'invite',verifier_hash,actor.actor,expiry,enc_key,1,sign_key,1,decode(p->>'bootstrap','base64'),manifest,1,digest);
    PERFORM wormhole_data.provision_invitation_login(issuance,p_verifier);
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'issue_member_invitation','success');
    RETURN 'published';
END
$publish$;
REVOKE ALL ON FUNCTION wormhole_api_v1.member_invitation_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text),
    wormhole_api_v1.publish_member_invitation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.member_invitation_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text),
    wormhole_api_v1.publish_member_invitation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,jsonb,text) TO wh_{{TAG}}_user;

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=103 WHERE singleton;
COMMIT;
