-- Version 85: audit maintenance and shared root custody during administrator recovery.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>84 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.maintain_audit_partitions(p_workspace uuid, p_retention_days integer DEFAULT 400)
RETURNS TABLE(partitions_created integer, partitions_dropped integer, expired_rows_deleted bigint)
LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' SET datestyle='ISO, YMD' SET lock_timeout='2s'
AS $maintain$
DECLARE
    checked_at constant timestamptz := pg_catalog.statement_timestamp();
    cutoff timestamptz;
    month_start timestamptz;
    month_end timestamptz;
    child record;
    child_name text;
BEGIN
    IF current_user<>'wh_{{TAG}}_owner' OR p_workspace IS DISTINCT FROM '{{WORKSPACE_ID}}'::uuid THEN
        RAISE EXCEPTION 'Audit maintenance requires the workspace owner and identity' USING ERRCODE='42501';
    END IF;
    IF p_retention_days IS NULL OR p_retention_days<1 THEN
        RAISE EXCEPTION 'Audit retention must be a positive number of days' USING ERRCODE='22023';
    END IF;
    cutoff := checked_at - pg_catalog.make_interval(days=>p_retention_days);
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace maintenance is already in progress' USING ERRCODE='55P03';
    END IF;
    LOCK TABLE ONLY wormhole_data.audit_log IN SHARE UPDATE EXCLUSIVE MODE NOWAIT;
    partitions_created := 0;
    partitions_dropped := 0;
    FOR child IN
        SELECT c.relname, n.nspname, c.relkind, pg_catalog.pg_get_expr(c.relpartbound,c.oid) AS bounds
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid=i.inhrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE i.inhparent='wormhole_data.audit_log'::regclass
        ORDER BY c.relname
    LOOP
        IF child.nspname<>'wormhole_data' OR child.relkind<>'r'
           OR child.relname !~ '^audit_log_[0-9]{4}(0[1-9]|1[0-2])$' THEN
            RAISE EXCEPTION 'Unexpected audit partition' USING ERRCODE='55000';
        END IF;
        month_start := pg_catalog.to_date(pg_catalog.right(child.relname,6),'YYYYMM')::timestamptz;
        month_end := month_start + interval '1 month';
        IF child.bounds IS DISTINCT FROM pg_catalog.format('FOR VALUES FROM (%L) TO (%L)',month_start,month_end) THEN
            RAISE EXCEPTION 'Unexpected audit partition bounds' USING ERRCODE='55000';
        END IF;
        IF month_end<=cutoff THEN
            EXECUTE pg_catalog.format('DROP TABLE wormhole_data.%I',child.relname);
            partitions_dropped := partitions_dropped + 1;
        END IF;
    END LOOP;

    FOR month_offset IN 0..2 LOOP
        month_start := pg_catalog.date_trunc('month',checked_at) + pg_catalog.make_interval(months=>month_offset);
        month_end := month_start + interval '1 month';
        child_name := 'audit_log_' || pg_catalog.to_char(month_start,'YYYYMM');
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_inherits i
                       WHERE i.inhparent='wormhole_data.audit_log'::regclass
                         AND i.inhrelid=pg_catalog.to_regclass(pg_catalog.format('wormhole_data.%I',child_name))) THEN
            EXECUTE pg_catalog.format(
                'CREATE TABLE wormhole_data.%I PARTITION OF wormhole_data.audit_log FOR VALUES FROM (%L) TO (%L)',
                child_name,month_start,month_end);
            partitions_created := partitions_created + 1;
        END IF;
    END LOOP;
    DELETE FROM wormhole_data.audit_log WHERE at<cutoff;
    GET DIAGNOSTICS expired_rows_deleted = ROW_COUNT;
    RETURN NEXT;
END
$maintain$;
REVOKE ALL ON FUNCTION wormhole_data.maintain_audit_partitions(uuid,integer)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

-- Suspending the last administrator queues its roots for rotation. The
-- existing invitation must still be able to deliver the current escrowed
-- workspace roots to its certified replacement before that rotation can run.
CREATE OR REPLACE FUNCTION wormhole_data.recovery_invitation_root_copy(p wormhole_data.key_copies) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $allowed$
    SELECT EXISTS(
        SELECT FROM wormhole_data.keys root
        JOIN wormhole_data.boundaries b ON b.id=root.owner_id AND b.owner_user_id IS NULL AND NOT b.deleted
        JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        JOIN wormhole_data.boundary_grants g ON g.boundary_id=b.id AND g.permissions=31
        JOIN wormhole_data.invites i ON i.user_id=g.user_id
        JOIN wormhole_data.workspace_admin_recovery r ON r.invite_id=i.id
        JOIN wormhole_data.keys holder ON (holder.key_id,holder.key_version)=(p.holder_key_id,p.holder_key_version)
            AND holder.owner_id=i.user_id AND holder.kind='user-enc'
        JOIN wormhole_data.keys issuer ON (issuer.key_id,issuer.key_version)=(p.issuer_key_id,p.issuer_key_version)
        WHERE (root.key_id,root.key_version)=(p.key_id,p.key_version) AND root.status='active'
          AND root.kind IN ('boundary-secret','boundary-view')
          AND (r.boundary_recovery OR NOT EXISTS (SELECT FROM wormhole_data.boundaries other
                   WHERE other.owner_user_id IS NULL AND NOT other.deleted AND other.id<>b.id))
          AND NOT wormhole_data.account_rotation_pending(p.holder_key_id,p.holder_key_version)
          AND NOT EXISTS (SELECT FROM wormhole_data.group_boundary_rotation_queue queued
                   WHERE (queued.root_id,queued.root_version)=(p.holder_key_id,p.holder_key_version))
          AND convert_from(m.body,'UTF8')::jsonb @> '{"active":true,"orgEscrow":true}'
          AND (convert_from(m.body,'UTF8')::jsonb ->
               (CASE root.kind WHEN 'boundary-secret' THEN 'secret' ELSE 'view' END) -> 'key')
              =jsonb_build_object('id',root.key_id,'version',root.key_version)
          AND (EXISTS (SELECT FROM wormhole_data.group_boundary_rotation_queue q
                   WHERE (q.boundary_id,q.root_id,q.root_version)=(b.id,root.key_id,root.key_version))
               OR EXISTS (SELECT FROM wormhole_data.account_suspension_roots s
                   JOIN wormhole_data.users u ON u.id=s.account_id AND u.disabled
                   WHERE (s.boundary_id,s.root_id,s.root_version)=(b.id,root.key_id,root.key_version)))
          AND i.kind='invite' AND i.used_at IS NULL AND i.expires_at>statement_timestamp()
          AND EXISTS (SELECT FROM jsonb_array_elements(convert_from(i.manifest,'UTF8')::jsonb->'copies') c
              WHERE c->'key'=jsonb_build_object('id',p.key_id,'version',p.key_version)
                AND c->'holder'=jsonb_build_object('id',i.bootstrap_enc_key_id,'version',i.bootstrap_enc_key_version))
          AND ((session_user='wh_{{TAG}}_deployer' AND holder.status='pending'
                 AND (holder.key_id,holder.key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version)
                 AND issuer.kind='org-sign' AND issuer.status='active' AND issuer.owner_id IS NULL)
            OR (holder.status='active' AND issuer.kind='user-sign' AND issuer.status='active' AND issuer.owner_id=i.user_id
                AND EXISTS (SELECT FROM wormhole_data.invitation_logins l JOIN pg_roles pr ON pr.oid=l.role_oid AND pr.rolname=l.role_name
                    WHERE l.invite_id=i.id AND l.role_name=session_user AND NOT l.revoked AND pr.rolcanlogin)
                AND EXISTS (SELECT FROM wormhole_data.key_copies source WHERE (source.key_id,source.key_version)=(p.key_id,p.key_version)
                    AND (source.holder_key_id,source.holder_key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version))))
    )
$allowed$;

-- The legacy checkpoint names one reviewed workspace boundary. Its invitation,
-- grant and recovery receipt must exist before the rotation guard sees a copy.
-- They commit in the same transaction as the copies and the login role.
CREATE OR REPLACE FUNCTION wormhole_api_v1.recover_workspace_admin(p jsonb,p_verifier text) RETURNS uuid
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
    INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES((proof->>'boundaryId')::uuid,actor,31);
    INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state)
    VALUES(actor,1,pg_catalog.decode(p->>'signedState','base64'));
    INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,
        bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision)
    VALUES(issuance,actor,'invite',pg_catalog.sha256(pg_catalog.convert_to(p_verifier,'UTF8')),actor,expires,enc,1,sign,1,
        pg_catalog.decode(p->>'bootstrap','base64'),pg_catalog.decode(p->>'manifest','base64'),1);
    PERFORM wormhole_data.provision_invitation_login(issuance,p_verifier);
    INSERT INTO wormhole_data.workspace_admin_recovery(invite_id,request_digest,boundary_recovery) VALUES(issuance,request_digest,false);
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
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(actor,pg_catalog.gen_random_uuid(),session_user,'ui','break_glass_recovery','invitation_published',pg_catalog.inet_client_addr(),'recovery-v1');
    RETURN issuance;
END
$recover$;

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=85 WHERE singleton;
COMMIT;
