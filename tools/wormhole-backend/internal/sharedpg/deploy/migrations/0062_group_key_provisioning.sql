-- Version 62: issue an organisation-certified encryption key for a group.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>61 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.groups ADD COLUMN key_manifest bytea CHECK(octet_length(key_manifest) BETWEEN 1 AND 4096);

{{GROUP_KEY_ROSTER_DEFINITION}}

CREATE FUNCTION wormhole_data.group_key_review(p_group uuid,p_revision bigint,p_roster bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $review$
    SELECT pg_catalog.sha256(convert_to('wormhole/v1/group-key-review:'||p_group::text||':'||p_revision::text||':','UTF8')||p_roster)
$review$;

CREATE FUNCTION wormhole_api_v1.group_key_material(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_group uuid,p_revision bigint,p_review bytea)
RETURNS TABLE(status text,roster bytea,manifest bytea,org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,
    recipient_id uuid,recipient_version integer,recipient_public bytea,recipient_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $material$
DECLARE actor record; item wormhole_data.groups; members record; signing record; recipient record;
BEGIN
    IF p_group IS NULL OR p_group='00000000-0000-0000-0000-000000000000'::uuid OR p_revision IS NULL OR p_revision<1
        OR (p_review IS NOT NULL AND octet_length(p_review)<>32) THEN
        RAISE EXCEPTION 'Invalid group key request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    SELECT * INTO item FROM wormhole_data.groups g WHERE g.id=p_group FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF item.key_manifest IS NOT NULL THEN
        status:='provisioned'; manifest:=item.key_manifest; RETURN NEXT; RETURN;
    END IF;
    IF item.row_version<>p_revision OR p_revision=9223372036854775807 THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF EXISTS(SELECT FROM wormhole_data.keys k WHERE k.kind='group' AND k.owner_id=p_group)
        OR EXISTS(SELECT FROM wormhole_data.boundary_grants b WHERE b.group_id=p_group) THEN
        status:='incomplete'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT members FROM wormhole_data.group_key_roster(p_group);
    IF members.status<>'ready' THEN status:=members.status; RETURN NEXT; RETURN; END IF;
    IF p_review IS NOT NULL AND wormhole_data.group_key_review(p_group,p_revision,members.body)<>p_review THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT k.* INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active'
        AND k.suite=2 AND octet_length(k.public_key)=32 AND k.cert_revision=1 AND octet_length(k.cert_signature)=64
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(signing.org_key_id,signing.org_key_version) FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    status:='ready'; roster:=members.body;
    IF p_review IS NOT NULL THEN
        org_key_id:=signing.org_key_id; org_key_version:=signing.org_key_version; enc:=signing.enc;
        ciphertext:=signing.ciphertext; signature:=signing.signature;
        recipient_id:=recipient.key_id; recipient_version:=recipient.key_version;
        recipient_public:=recipient.public_key; recipient_signature:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'group_key_signer','key_copy_released');
    END IF;
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::bytea,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea;
END
$material$;

CREATE FUNCTION wormhole_api_v1.commit_group_key(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_group uuid,p_revision bigint,p_manifest text,p_copies jsonb)
RETURNS TABLE(status text,manifest bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $commit$
DECLARE actor record; item wormhole_data.groups; recipients record; signing record; recipient record;
    body jsonb; roster jsonb; copy jsonb; binding jsonb; envelope jsonb; holder uuid; holder_version integer;
    group_key uuid; group_public bytea; proof bytea; wrapped bytea; encapsulated bytea; i integer; member_list integer;
BEGIN
    IF p_group IS NULL OR p_revision IS NULL OR p_revision<1 OR p_revision=9223372036854775807
        OR COALESCE(octet_length(p_manifest),0) NOT BETWEEN 2 AND 4096
        OR jsonb_typeof(p_copies) IS DISTINCT FROM 'array' OR octet_length(p_copies::text)>65536 THEN
        RAISE EXCEPTION 'Invalid group key publication' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,true);
    SELECT * INTO item FROM wormhole_data.groups g WHERE g.id=p_group FOR UPDATE NOWAIT;
    IF NOT FOUND THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF item.key_manifest IS NOT NULL THEN
        status:='provisioned'; manifest:=item.key_manifest; RETURN NEXT; RETURN;
    END IF;
    IF item.row_version<>p_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF EXISTS(SELECT FROM wormhole_data.keys k WHERE k.kind='group' AND k.owner_id=p_group)
        OR EXISTS(SELECT FROM wormhole_data.boundary_grants b WHERE b.group_id=p_group) THEN
        status:='incomplete'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT recipients FROM wormhole_data.group_key_roster(p_group);
    IF recipients.status<>'ready' THEN status:=recipients.status; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT k.* INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active'
        AND k.suite=2 AND octet_length(k.public_key)=32 AND k.cert_revision=1 AND octet_length(k.cert_signature)=64
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(signing.org_key_id,signing.org_key_version) FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    body:=p_manifest::jsonb;
    IF body->>'rosterDigest' IS DISTINCT FROM encode(wormhole_data.group_key_review(p_group,p_revision,recipients.body),'base64') THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    roster:=convert_from(recipients.body,'UTF8')::jsonb;
    member_list:=jsonb_array_length(roster);
    proof:=decode(body->>'signature','base64');
    group_key:=(body#>>'{key,key,id}')::uuid;
    group_public:=decode(body#>>'{key,public}','base64');
    IF body->'formatVersion' IS DISTINCT FROM '1'::jsonb OR body->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}'
        OR body->>'groupId' IS DISTINCT FROM p_group::text OR body->>'groupRevision' IS DISTINCT FROM p_revision::text
        OR body->'signer' IS DISTINCT FROM jsonb_build_object('id',signing.org_key_id,'version',signing.org_key_version)
        OR body->'recovery' IS DISTINCT FROM jsonb_build_object('id',recipient.key_id,'version',recipient.key_version)
        OR body#>'{key,key,version}' IS DISTINCT FROM '1'::jsonb OR group_key IS NULL
        OR octet_length(group_public) IS DISTINCT FROM 32 OR octet_length(proof) IS DISTINCT FROM 64
        OR jsonb_array_length(p_copies)<>member_list+1 THEN
        RAISE EXCEPTION 'Invalid group key manifest' USING ERRCODE='22023';
    END IF;
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key) VALUES(group_key,1,'group',p_group,2,group_public);
    FOR i IN 0..member_list LOOP
        copy:=p_copies->i; binding:=copy->'binding'; envelope:=copy->'envelope';
        holder:=CASE WHEN i=member_list THEN recipient.key_id ELSE (roster->i->>1)::uuid END;
        holder_version:=CASE WHEN i=member_list THEN recipient.key_version ELSE (roster->i->>2)::integer END;
        proof:=decode(copy->>'signature','base64');
        wrapped:=decode(envelope->>'ciphertext','base64');
        encapsulated:=decode(envelope->>'enc','base64');
        IF binding->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}'
            OR binding->'key' IS DISTINCT FROM body#>'{key,key}'
            OR binding->'holder' IS DISTINCT FROM jsonb_build_object('id',holder,'version',holder_version)
            OR binding->'issuer' IS DISTINCT FROM body->'signer'
            OR envelope->'formatVersion' IS DISTINCT FROM '1'::jsonb OR envelope->'suiteId' IS DISTINCT FROM '2'::jsonb
            OR octet_length(proof) IS DISTINCT FROM 64 OR octet_length(wrapped) IS DISTINCT FROM 48
            OR octet_length(encapsulated) IS DISTINCT FROM 32 THEN
            RAISE EXCEPTION 'Invalid group key copy' USING ERRCODE='22023';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(group_key,1,holder,holder_version,2,encapsulated,wrapped,signing.org_key_id,signing.org_key_version,proof);
    END LOOP;
    manifest:=convert_to(p_manifest,'UTF8');
    UPDATE wormhole_data.groups SET key_manifest=manifest,row_version=row_version+1 WHERE id=p_group;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,admin_group_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','group_key_provision','success',pg_catalog.inet_client_addr(),actor.app_version,p_group);
    status:='issued';
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea;
END
$commit$;

CREATE FUNCTION wormhole_data.group_keys_recoverable(p_workspace uuid) RETURNS boolean
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $recoverable$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.groups g
        CROSS JOIN LATERAL (SELECT convert_from(g.key_manifest,'UTF8')::jsonb AS body) m
        WHERE g.key_manifest IS NOT NULL AND (
            m.body->>'workspaceId' IS DISTINCT FROM p_workspace::text OR m.body->>'groupId' IS DISTINCT FROM g.id::text
            OR NOT EXISTS(
                SELECT FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING(key_id,key_version)
                JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
                WHERE k.kind='group' AND k.owner_id=g.id AND k.status='active'
                    AND (k.key_id::text,k.key_version::text)=(m.body#>>'{key,key,id}',m.body#>>'{key,key,version}')
                    AND k.public_key=decode(m.body#>>'{key,public}','base64')
                    AND h.kind='org-enc' AND h.owner_id IS NULL AND h.status='active'
                    AND (h.key_id::text,h.key_version::text)=(m.body#>>'{recovery,id}',m.body#>>'{recovery,version}')
                    AND (c.issuer_key_id::text,c.issuer_key_version::text)=(m.body#>>'{signer,id}',m.body#>>'{signer,version}')
                    AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
            )
        )
    )
$recoverable$;

{{GROUP_KEYS_EXPORT_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.group_key_roster(uuid),wormhole_data.group_key_review(uuid,bigint,bytea),
    wormhole_data.group_keys_recoverable(uuid) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_api_v1.group_key_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea),
    wormhole_api_v1.commit_group_key(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,text,jsonb)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.group_key_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea),
    wormhole_api_v1.commit_group_key(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,text,jsonb) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=62 WHERE singleton;
COMMIT;
