-- Version 72: retire shared boundary roots captured at account suspension.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>71 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE INDEX account_suspension_roots_by_key ON wormhole_data.account_suspension_roots(root_id,root_version);

CREATE FUNCTION wormhole_data.account_rotation_pending(p_key uuid,p_version integer) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $pending$
    SELECT EXISTS(
        SELECT FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.users u ON u.id=r.account_id
        JOIN wormhole_data.boundaries b ON b.id=r.boundary_id
        JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(r.root_id,r.root_version)
        WHERE (r.root_id,r.root_version)=(p_key,p_version) AND u.disabled
            AND b.owner_user_id IS NULL AND NOT b.deleted AND k.status='active'
            AND convert_from(m.body,'UTF8')::jsonb @> '{"active":true,"orgEscrow":true}'
    )
$pending$;

CREATE OR REPLACE FUNCTION wormhole_data.guard_pending_rotation_copy() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q
        WHERE (q.root_id,q.root_version) IN ((NEW.key_id,NEW.key_version),(NEW.holder_key_id,NEW.holder_key_version)))
        OR wormhole_data.account_rotation_pending(NEW.key_id,NEW.key_version)
        OR wormhole_data.account_rotation_pending(NEW.holder_key_id,NEW.holder_key_version) THEN
        IF TG_OP='INSERT' AND wormhole_data.recovery_invitation_root_copy(NEW) THEN RETURN NEW; END IF;
        RAISE EXCEPTION 'Boundary root is awaiting rotation' USING ERRCODE='WH020';
    END IF;
    RETURN NEW;
END
$guard$;

CREATE OR REPLACE FUNCTION wormhole_data.guard_pending_rotation_value() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(NEW.dek_id,NEW.dek_version)
        AND (wormhole_data.account_rotation_pending(c.holder_key_id,c.holder_key_version)
            OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q
                WHERE (q.root_id,q.root_version)=(c.holder_key_id,c.holder_key_version)))) THEN
        RAISE EXCEPTION 'Boundary value is awaiting rotation' USING ERRCODE='WH020';
    END IF;
    RETURN NEW;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.rotate_account_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_account uuid,p_suspension bigint,p_boundary uuid,purpose_mask integer,p_key uuid,p_key_version integer,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,graph jsonb,sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,org_public bytea,org_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex' AS $rotate$
DECLARE actor record; boundary wormhole_data.boundaries; manifest wormhole_data.boundary_manifests; meta record;
    org_signing record; org_encryption record; recipient wormhole_data.keys; old_status text; purpose text;
    old jsonb; next_graph jsonb; document bytea;
BEGIN
    IF p_account IS NULL OR p_boundary IS NULL OR p_suspension IS NULL OR p_suspension<1 OR p_key IS NULL OR
        p_key_version IS NULL OR p_key_version NOT BETWEEN 1 AND 2147483646 OR purpose_mask IS NULL OR purpose_mask NOT IN (1,2)
        OR '00000000-0000-0000-0000-000000000000'::uuid IN (p_account,p_boundary,p_key)
        OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object'
            OR octet_length(p_publication::text)>16777216)) THEN
        RAISE EXCEPTION 'Invalid suspended account rotation request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    SELECT * INTO boundary FROM wormhole_data.boundaries b
        WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE NOWAIT;
    IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&(17|purpose_mask))<>(17|purpose_mask) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS(SELECT FROM wormhole_data.account_suspensions s JOIN wormhole_data.users u ON u.id=s.account_id
        WHERE s.account_id=p_account AND s.revision=p_suspension AND u.disabled FOR SHARE OF u NOWAIT) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT k.status INTO old_status FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(r.root_id,r.root_version)
        WHERE (r.account_id,r.boundary_id,r.purpose,r.root_id,r.root_version)=(p_account,p_boundary,purpose_mask,p_key,p_key_version);
    IF NOT FOUND THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF old_status='retired' THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO manifest FROM wormhole_data.boundary_manifests m WHERE m.boundary_id=p_boundary FOR SHARE NOWAIT;
    IF NOT FOUND OR manifest.version=9223372036854775807 OR old_status<>'active' THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    purpose:=CASE purpose_mask WHEN 1 THEN 'view' ELSE 'secret' END;
    old:=convert_from(manifest.body,'UTF8')::jsonb;
    IF old->>'active' IS DISTINCT FROM 'true' OR old->>'orgEscrow' IS DISTINCT FROM 'true'
        OR old->>'previousView' IS NOT NULL OR old->>'previousSecret' IS NOT NULL
        OR old#>ARRAY[purpose,'key'] IS DISTINCT FROM jsonb_build_object('id',p_key,'version',p_key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    -- Existing group workers settle their queues and may retire this same root.
    -- Also require a fresh group key if the suspended account still holds a
    -- certified copy of a group's current key for this purpose.
    IF EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE (q.root_id,q.root_version)=(p_key,p_key_version))
        OR EXISTS(
            SELECT FROM wormhole_data.key_copies root_wrap
            JOIN wormhole_data.keys team ON (team.key_id,team.key_version)=(root_wrap.holder_key_id,root_wrap.holder_key_version)
            JOIN wormhole_data.boundary_grants g ON g.boundary_id=p_boundary AND g.group_id=team.owner_id AND (g.permissions&purpose_mask)<>0
            JOIN wormhole_data.key_copies group_wrap ON (group_wrap.key_id,group_wrap.key_version)=(team.key_id,team.key_version)
            JOIN wormhole_data.keys member ON (member.key_id,member.key_version)=(group_wrap.holder_key_id,group_wrap.holder_key_version)
            WHERE (root_wrap.key_id,root_wrap.key_version)=(p_key,p_key_version)
                AND team.kind='group' AND team.status='active' AND member.kind='user-enc' AND member.owner_id=p_account
        ) THEN status:='group-rotation-required'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(manifest.signer_key_id,manifest.signer_key_version)
        AND k.cert_revision=1 AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton;
    BEGIN
        next_graph:=wormhole_data.boundary_rotation_graph(p_boundary,NULL,purpose_mask,old,recipient.key_id,recipient.key_version,
            meta.epoch,meta.change_seq);
    EXCEPTION WHEN SQLSTATE 'WH020' THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END;
    document:=convert_to(jsonb_build_object('accountId',p_account,'suspension',p_suspension::text,'boundaryId',p_boundary,
        'root',jsonb_build_object('id',p_key,'version',p_key_version),'affected',purpose_mask,
        'epoch',meta.epoch::text,'changeSeq',meta.change_seq::text,'boundary',encode(manifest.body,'hex'),
        'recovery',jsonb_build_object('id',recipient.key_id,'version',recipient.key_version),
        'graphDigest',encode(sha256(convert_to(next_graph::text,'UTF8')),'hex'))::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/account-boundary-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    IF (org_signing.org_key_id,org_signing.org_key_version)<>(manifest.signer_key_id,manifest.signer_key_version)
        OR (org_encryption.org_key_id,org_encryption.org_key_version)<>(recipient.key_id,recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; snapshot:=document; graph:=next_graph;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version; org_enc:=org_encryption.enc;
        org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'account_boundary_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    PERFORM wormhole_data.publish_boundary_rotation(p_boundary,old,next_graph,p_publication);
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        admin_boundary_id,access_account_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','account_boundary_rotation','success',inet_client_addr(),
           actor.app_version,p_boundary,p_account);
    status:='changed'; snapshot:=convert_to(p_publication->>'manifest','UTF8'); RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::jsonb,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea;
END
$rotate$;

-- An account's related groups must all be able to retire their old group
-- generation before the joint worker replaces a shared boundary root.
{{ACCOUNT_GROUP_ROTATION_SCOPE}}
DROP FUNCTION wormhole_data.group_member_rotation_scope(uuid,uuid,integer);
{{SUSPENSION_RESTORE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.account_rotation_pending(uuid,integer),
    wormhole_api_v1.rotate_account_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,integer,uuid,integer,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION
    wormhole_api_v1.rotate_account_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,integer,uuid,integer,bytea,jsonb)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=72 WHERE singleton;
COMMIT;
