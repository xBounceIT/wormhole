-- Version 64: publish additions to shared boundary grants with their key copies.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>63 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.audit_log ADD COLUMN admin_boundary_id uuid;

CREATE FUNCTION wormhole_api_v1.grant_group_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_node uuid,p_node_revision bigint,p_boundary uuid,p_group uuid,p_group_revision bigint,p_mask integer,p_review bytea,p_copies jsonb)
RETURNS TABLE(status text,snapshot bytea,roster bytea,sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,
    org_public bytea,org_certificate bytea,escrow jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $grant$
DECLARE actor record; meta record; target wormhole_data.nodes; boundary wormhole_data.boundaries;
    b_manifest wormhole_data.boundary_manifests; team wormhole_data.groups; selected wormhole_data.boundary_grants;
    group_doc jsonb; boundary_doc jsonb; members record; group_key wormhole_data.keys; recipient wormhole_data.keys;
    org_signing record; org_encryption record; refs jsonb:='[]'; root record;
    key_id_to_wrap uuid; key_version_to_wrap integer; kind_to_wrap text; root_ref jsonb; present boolean;
    bit integer; previous_mask integer; added integer; position integer:=0; issuer jsonb; document bytea;
    wrapped jsonb; binding jsonb; envelope jsonb; enc_bytes bytea; wrapped_bytes bytea; proof bytea;
BEGIN
    IF p_node IS NULL OR p_boundary IS NULL OR p_group IS NULL OR p_node_revision IS NULL OR p_group_revision IS NULL
        OR p_node_revision<1 OR p_group_revision<1 OR p_mask IS NULL OR p_mask NOT IN (1,2,3)
        OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_copies IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_copies)<>'array' OR octet_length(p_copies::text)>4096)) THEN
        RAISE EXCEPTION 'Invalid group boundary grant' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_copies IS NOT NULL);
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT * INTO target FROM wormhole_data.nodes n WHERE n.id=p_node FOR SHARE NOWAIT;
    IF NOT FOUND OR target.boundary_id IS DISTINCT FROM p_boundary OR (wormhole_data.effective_permissions(actor.actor,p_node)&17)<>17
        OR EXISTS(WITH RECURSIVE ancestry(id,parent_id,owner_user_id) AS (
            SELECT target.id,target.parent_id,target.owner_user_id
            UNION
            SELECT n.id,n.parent_id,n.owner_user_id FROM ancestry a JOIN wormhole_data.nodes n ON n.id=a.parent_id
        ) SELECT FROM ancestry WHERE owner_user_id IS NOT NULL) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF target.row_version<>p_node_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO boundary FROM wormhole_data.boundaries b WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE NOWAIT;
    IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&(16|p_mask))<>(16|p_mask) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO team FROM wormhole_data.groups g WHERE g.id=p_group FOR SHARE NOWAIT;
    IF NOT FOUND OR team.row_version<>p_group_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF team.key_manifest IS NULL THEN status:='key-required'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO b_manifest FROM wormhole_data.boundary_manifests b WHERE b.boundary_id=p_boundary FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    boundary_doc:=convert_from(b_manifest.body,'UTF8')::jsonb;
    group_doc:=convert_from(team.key_manifest,'UTF8')::jsonb;
    IF boundary_doc->>'active' IS DISTINCT FROM 'true' OR boundary_doc->>'orgEscrow' IS DISTINCT FROM 'true' THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF boundary_doc->>'previousView' IS NOT NULL OR boundary_doc->>'previousSecret' IS NOT NULL THEN
        status:='rotation-required'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT members FROM wormhole_data.group_key_roster(p_group);
    IF members.status<>'ready' OR
        group_doc->>'rosterDigest' IS DISTINCT FROM encode(wormhole_data.group_key_review(p_group,(group_doc->>'groupRevision')::bigint,members.body),'base64') THEN
        status:='rotation-required'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO group_key FROM wormhole_data.keys k WHERE k.kind='group' AND k.owner_id=p_group AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((group_doc#>>'{key,key,id}')::uuid,(group_doc#>>'{key,key,version}')::integer)
        AND k.public_key=decode(group_doc#>>'{key,public}','base64') FOR SHARE NOWAIT;
    IF NOT FOUND OR EXISTS(SELECT FROM jsonb_array_elements(convert_from(members.body,'UTF8')::jsonb) member
        WHERE NOT EXISTS(SELECT FROM wormhole_data.key_copies c
            WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)=(group_key.key_id,group_key.key_version,(member->>1)::uuid,(member->>2)::integer)
              AND (c.issuer_key_id,c.issuer_key_version)=(b_manifest.signer_key_id,b_manifest.signer_key_version)
              AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48)) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO selected FROM wormhole_data.boundary_grants g WHERE g.boundary_id=p_boundary AND g.group_id=p_group FOR SHARE NOWAIT;
    previous_mask:=COALESCE(selected.permissions,0);
    IF selected.signature IS NOT NULL OR (previous_mask & p_mask)<>previous_mask THEN
        status:='rotation-required'; RETURN NEXT; RETURN;
    END IF;
    added:=p_mask & ~previous_mask;
    FOR bit IN 0..1 LOOP
        IF (p_mask & (1<<bit))=0 THEN CONTINUE; END IF;
        root_ref:=boundary_doc#>ARRAY[CASE WHEN bit=0 THEN 'view' ELSE 'secret' END,'key'];
        key_id_to_wrap:=(root_ref->>'id')::uuid;
        key_version_to_wrap:=(root_ref->>'version')::integer;
        kind_to_wrap:=CASE WHEN bit=0 THEN 'boundary-view' ELSE 'boundary-secret' END;
        IF NOT EXISTS(SELECT FROM wormhole_data.keys k WHERE (k.key_id,k.key_version)=(key_id_to_wrap,key_version_to_wrap)
            AND k.kind=kind_to_wrap AND k.owner_id=p_boundary AND k.status='active' AND k.suite=2) THEN
            status:='unavailable'; RETURN NEXT; RETURN;
        END IF;
        SELECT EXISTS(SELECT FROM wormhole_data.key_copies c
            WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)=(key_id_to_wrap,key_version_to_wrap,group_key.key_id,group_key.key_version)
              AND (c.issuer_key_id,c.issuer_key_version)=(b_manifest.signer_key_id,b_manifest.signer_key_version)
              AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48) INTO present;
        IF present IS DISTINCT FROM ((previous_mask & (1<<bit))<>0) THEN
            status:='unavailable'; RETURN NEXT; RETURN;
        END IF;
        IF (added & (1<<bit))<>0 THEN refs:=refs||jsonb_build_array(root_ref); END IF;
    END LOOP;
    IF added=0 THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    document:=convert_to(jsonb_build_object('nodeId',p_node,'nodeRevision',p_node_revision::text,
        'boundaryId',p_boundary,'boundaryRevision',boundary.row_version::text,'boundary',encode(b_manifest.body,'hex'),
        'groupId',p_group,'groupRevision',p_group_revision::text,'group',encode(team.key_manifest,'hex'),
        'grantRevision',COALESCE(selected.row_version,0)::text,'mask',p_mask,'previousMask',previous_mask)::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/group-boundary-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; roster:=members.body; RETURN NEXT; RETURN; END IF;

    issuer:=jsonb_build_object('id',b_manifest.signer_key_id,'version',b_manifest.signer_key_version);
    IF group_doc->'signer' IS DISTINCT FROM issuer THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    SELECT * INTO recipient FROM wormhole_data.keys k
        WHERE (k.key_id,k.key_version)=(org_encryption.org_key_id,org_encryption.org_key_version)
          AND (k.cert_signer_key_id,k.cert_signer_key_version)=(org_signing.org_key_id,org_signing.org_key_version)
          AND k.cert_revision=1 AND k.suite=2 AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND OR (org_signing.org_key_id,org_signing.org_key_version)<>(b_manifest.signer_key_id,b_manifest.signer_key_version)
        OR group_doc->'recovery' IS DISTINCT FROM jsonb_build_object('id',recipient.key_id,'version',recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_copies IS NULL THEN
        escrow:='[]';
        FOR root_ref IN SELECT value FROM jsonb_array_elements(refs) LOOP
            SELECT * INTO STRICT root FROM wormhole_data.key_copy_record((root_ref->>'id')::uuid,(root_ref->>'version')::integer,
                recipient.key_id,recipient.key_version,meta.epoch,meta.change_seq);
            escrow:=escrow||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(root)));
        END LOOP;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version; org_enc:=org_encryption.enc;
        org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        status:='ready'; snapshot:=document; roster:=members.body;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'group_boundary_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    IF jsonb_array_length(p_copies)<>jsonb_array_length(refs) THEN
        RAISE EXCEPTION 'Invalid boundary copy count' USING ERRCODE='22023';
    END IF;
    FOR root_ref IN SELECT value FROM jsonb_array_elements(refs) LOOP
        wrapped:=p_copies->position; binding:=wrapped->'binding'; envelope:=wrapped->'envelope';
        proof:=decode(wrapped->>'signature','base64');
        enc_bytes:=decode(envelope->>'enc','base64'); wrapped_bytes:=decode(envelope->>'ciphertext','base64');
        IF binding->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR binding->'key' IS DISTINCT FROM root_ref
            OR binding->'holder' IS DISTINCT FROM group_doc#>'{key,key}' OR binding->'issuer' IS DISTINCT FROM issuer
            OR envelope->'formatVersion' IS DISTINCT FROM '1'::jsonb OR envelope->'suiteId' IS DISTINCT FROM '2'::jsonb
            OR octet_length(proof) IS DISTINCT FROM 64 OR octet_length(enc_bytes) IS DISTINCT FROM 32 OR octet_length(wrapped_bytes) IS DISTINCT FROM 48 THEN
            RAISE EXCEPTION 'Invalid boundary copy' USING ERRCODE='22023';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES((root_ref->>'id')::uuid,(root_ref->>'version')::integer,group_key.key_id,group_key.key_version,2,
            enc_bytes,wrapped_bytes,b_manifest.signer_key_id,b_manifest.signer_key_version,proof);
        position:=position+1;
    END LOOP;
    IF previous_mask=0 THEN
        INSERT INTO wormhole_data.boundary_grants(boundary_id,group_id,permissions) VALUES(p_boundary,p_group,p_mask);
    ELSE
        UPDATE wormhole_data.boundary_grants g SET permissions=p_mask,row_version=g.row_version+1 WHERE g.boundary_id=p_boundary AND g.group_id=p_group;
    END IF;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        node_id,admin_boundary_id,admin_grant_subject_id,admin_grant_subject_kind,admin_grant_before,admin_grant_after)
    VALUES(actor.actor,actor.session_id,session_user,'ui','boundary_group_grant','success',inet_client_addr(),
        actor.app_version,p_node,p_boundary,p_group,'group',previous_mask,p_mask);
    status:='changed'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    status:='busy'; snapshot:=NULL; roster:=NULL;
    sign_id:=NULL; sign_version:=NULL; sign_enc:=NULL; sign_ciphertext:=NULL; sign_proof:=NULL;
    org_id:=NULL; org_version:=NULL; org_enc:=NULL; org_ciphertext:=NULL; org_proof:=NULL;
    org_public:=NULL; org_certificate:=NULL; escrow:=NULL;
    RETURN NEXT;
END
$grant$;

{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.grant_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.grant_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=64 WHERE singleton;
COMMIT;
