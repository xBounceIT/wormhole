-- Private publication validates the complete retained graph before activation.
-- Its caller owns the workspace and authorization row locks for this snapshot.
CREATE FUNCTION wormhole_data.publish_boundary_rotation(p_boundary uuid,p_old jsonb,p_graph jsonb,p_publication jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $publish$
DECLARE next_raw text; next_doc jsonb; issuer jsonb; copies jsonb; result jsonb; binding jsonb; sealed jsonb; root jsonb;
    purpose text; source jsonb; destination jsonb; expected record; old_id uuid; old_version integer;
    position integer:=0; proof bytea; encapsulated bytea; ciphertext bytea; next_public bytea;
BEGIN
    next_raw:=p_publication->>'manifest';
    copies:=p_publication->'copies';
    IF octet_length(next_raw) IS NULL OR octet_length(next_raw)>8192 OR jsonb_typeof(copies) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'Invalid boundary rotation publication' USING ERRCODE='22023';
    END IF;
    next_doc:=next_raw::jsonb;
    issuer:=p_old->'signer';
    proof:=decode(next_doc->>'signature','base64');
    IF (next_doc-ARRAY['revision','signature','view','secret']) IS DISTINCT FROM (p_old-ARRAY['revision','signature','view','secret'])
        OR next_doc->'revision' IS DISTINCT FROM to_jsonb((p_old->>'revision')::bigint+1)
        OR octet_length(proof) IS DISTINCT FROM 64 OR next_doc#>'{view,public}' IS NOT DISTINCT FROM next_doc#>'{secret,public}' THEN
        RAISE EXCEPTION 'Invalid replacement boundary manifest' USING ERRCODE='22023';
    END IF;
    FOREACH purpose IN ARRAY ARRAY['view','secret'] LOOP
        SELECT value INTO root FROM jsonb_array_elements(p_graph) WHERE value->>'purpose'=purpose;
        source:=p_old->purpose;
        destination:=next_doc->purpose;
        IF NOT FOUND THEN
            IF destination IS DISTINCT FROM source THEN RAISE EXCEPTION 'Unreviewed root replacement' USING ERRCODE='22023'; END IF;
            CONTINUE;
        END IF;
        old_id:=(source#>>'{key,id}')::uuid;
        old_version:=(source#>>'{key,version}')::integer;
        next_public:=decode(destination->>'public','base64');
        IF destination->'key' IS DISTINCT FROM jsonb_build_object('id',old_id,'version',old_version+1)
            OR octet_length(next_public) IS DISTINCT FROM 32 OR destination->'public' IS NOT DISTINCT FROM source->'public' THEN
            RAISE EXCEPTION 'Invalid replacement root' USING ERRCODE='22023';
        END IF;
        UPDATE wormhole_data.keys SET status='retired',row_version=row_version+1
            WHERE (key_id,key_version)=(old_id,old_version) AND kind='boundary-'||purpose AND owner_id=p_boundary AND status='active';
        IF NOT FOUND THEN RAISE EXCEPTION 'Boundary root changed' USING ERRCODE='WH013'; END IF;
        INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
        VALUES(old_id,old_version+1,'boundary-'||purpose,p_boundary,2,next_public);
        FOR expected IN
            SELECT destination->'key' AS key_ref,r.value->'key' AS holder,0 AS kind,r.ordinality AS position
                FROM jsonb_array_elements(root->'recipients') WITH ORDINALITY r
            UNION ALL
            SELECT jsonb_build_object('id',(d.value->>3)::uuid,'version',(d.value->>4)::integer),destination->'key',1,d.ordinality
                FROM jsonb_array_elements(root->'deks') WITH ORDINALITY d
            ORDER BY 3,4
        LOOP
            result:=copies->position; binding:=result->'binding'; sealed:=result->'copy'->'envelope';
            encapsulated:=decode(sealed->>'enc','base64'); ciphertext:=decode(sealed->>'ciphertext','base64');
            proof:=decode(result->'copy'->>'signature','base64');
            IF binding->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR binding->'key' IS DISTINCT FROM expected.key_ref
                OR binding->'holder' IS DISTINCT FROM expected.holder OR binding->'issuer' IS DISTINCT FROM issuer
                OR sealed->'formatVersion' IS DISTINCT FROM '1'::jsonb OR sealed->'suiteId' IS DISTINCT FROM '2'::jsonb
                OR octet_length(encapsulated) IS DISTINCT FROM 32 OR octet_length(ciphertext) IS DISTINCT FROM 48 OR octet_length(proof) IS DISTINCT FROM 64 THEN
                RAISE EXCEPTION 'Invalid rotation copy coordinates' USING ERRCODE='22023';
            END IF;
            INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
            VALUES((expected.key_ref->>'id')::uuid,(expected.key_ref->>'version')::integer,(expected.holder->>'id')::uuid,(expected.holder->>'version')::integer,
                2,encapsulated,ciphertext,(issuer->>'id')::uuid,(issuer->>'version')::integer,proof);
            position:=position+1;
        END LOOP;
        DELETE FROM wormhole_data.key_copies WHERE (key_id,key_version)=(old_id,old_version) OR (holder_key_id,holder_key_version)=(old_id,old_version);
    END LOOP;
    IF jsonb_array_length(copies)<>position THEN RAISE EXCEPTION 'Unreviewed rotation copies' USING ERRCODE='22023'; END IF;
    UPDATE wormhole_data.boundary_manifests SET version=(next_doc->>'revision')::bigint,body=convert_to(next_raw,'UTF8'),
        signature=decode(next_doc->>'signature','base64') WHERE boundary_id=p_boundary;
    UPDATE wormhole_data.boundaries SET row_version=row_version+1 WHERE id=p_boundary;
END
$publish$;

CREATE FUNCTION wormhole_api_v1.rotate_group_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_node uuid,p_node_revision bigint,p_boundary uuid,p_group uuid,p_group_revision bigint,p_mask integer,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,graph jsonb,sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,org_public bytea,org_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex' AS $rotate$
DECLARE actor record; meta record; target wormhole_data.nodes; boundary wormhole_data.boundaries; team wormhole_data.groups;
    bound wormhole_data.boundary_manifests; selected wormhole_data.boundary_grants; old_manifest jsonb; old_group jsonb;
    org_signing record; org_encryption record; recipient wormhole_data.keys; rotation_graph jsonb; document bytea; removed integer;
BEGIN
    IF p_node IS NULL OR p_boundary IS NULL OR p_group IS NULL OR p_node_revision IS NULL OR p_group_revision IS NULL
        OR p_node_revision<1 OR p_group_revision<1 OR p_mask IS NULL OR p_mask NOT IN (0,1,2)
        OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object' OR octet_length(p_publication::text)>16777216)) THEN
        RAISE EXCEPTION 'Invalid boundary rotation request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT * INTO target FROM wormhole_data.nodes n WHERE n.id=p_node FOR SHARE NOWAIT;
    IF NOT FOUND OR target.boundary_id IS DISTINCT FROM p_boundary OR (wormhole_data.effective_permissions(actor.actor,p_node)&17)<>17
        OR EXISTS(WITH RECURSIVE ancestry(id,parent_id,owner_user_id) AS (
            SELECT target.id,target.parent_id,target.owner_user_id
            UNION SELECT n.id,n.parent_id,n.owner_user_id FROM ancestry a JOIN wormhole_data.nodes n ON n.id=a.parent_id
        ) SELECT FROM ancestry WHERE owner_user_id IS NOT NULL) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF target.row_version<>p_node_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
{{BOUNDARY_ROTATION_PENDING_GUARD}}
    SELECT * INTO boundary FROM wormhole_data.boundaries b WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE NOWAIT;
    IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&16)<>16 THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO team FROM wormhole_data.groups g WHERE g.id=p_group FOR SHARE NOWAIT;
    IF NOT FOUND OR team.row_version<>p_group_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF team.key_manifest IS NULL THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO selected FROM wormhole_data.boundary_grants g WHERE g.boundary_id=p_boundary AND g.group_id=p_group FOR SHARE NOWAIT;
    IF COALESCE(selected.permissions,0)=p_mask THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    IF NOT FOUND OR selected.permissions>3 OR selected.signature IS NOT NULL OR (p_mask & selected.permissions)<>p_mask THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    removed:=selected.permissions & ~p_mask;
    IF (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&removed)<>removed THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO bound FROM wormhole_data.boundary_manifests b WHERE b.boundary_id=p_boundary FOR SHARE NOWAIT;
    IF NOT FOUND OR bound.version=9223372036854775807 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    old_manifest:=convert_from(bound.body,'UTF8')::jsonb;
    old_group:=convert_from(team.key_manifest,'UTF8')::jsonb;
    IF old_manifest->>'active' IS DISTINCT FROM 'true' OR old_manifest->>'orgEscrow' IS DISTINCT FROM 'true'
        OR old_manifest->>'previousView' IS NOT NULL OR old_manifest->>'previousSecret' IS NOT NULL
        OR old_group->'signer' IS DISTINCT FROM old_manifest->'signer' THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((old_group#>>'{recovery,id}')::uuid,(old_group#>>'{recovery,version}')::integer)
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(bound.signer_key_id,bound.signer_key_version) AND k.cert_revision=1
        AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    rotation_graph:=wormhole_data.boundary_rotation_graph(p_boundary,p_group,removed,old_manifest,recipient.key_id,recipient.key_version,
        meta.epoch,meta.change_seq);
    document:=convert_to(jsonb_build_object('nodeId',p_node,'nodeRevision',p_node_revision::text,'boundaryId',p_boundary,
        'boundaryRevision',boundary.row_version::text,'groupId',p_group,'groupRevision',p_group_revision::text,
        'mask',p_mask,'previousMask',selected.permissions,'grantRevision',selected.row_version::text,
        'epoch',meta.epoch::text,'changeSeq',meta.change_seq::text,'boundary',encode(bound.body,'hex'),'group',encode(team.key_manifest,'hex'),
        'graphDigest',encode(sha256(convert_to(rotation_graph::text,'UTF8')),'hex'))::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/boundary-rotation-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; RETURN NEXT; RETURN; END IF;

    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    IF (org_signing.org_key_id,org_signing.org_key_version)<>(bound.signer_key_id,bound.signer_key_version)
        OR (org_encryption.org_key_id,org_encryption.org_key_version)<>(recipient.key_id,recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; snapshot:=document; graph:=rotation_graph;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version; org_enc:=org_encryption.enc;
        org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'boundary_rotation_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    PERFORM wormhole_data.publish_boundary_rotation(p_boundary,old_manifest,rotation_graph,p_publication);
    IF p_mask=0 THEN DELETE FROM wormhole_data.boundary_grants g WHERE g.boundary_id=p_boundary AND g.group_id=p_group;
    ELSE UPDATE wormhole_data.boundary_grants g SET permissions=p_mask,row_version=g.row_version+1 WHERE g.boundary_id=p_boundary AND g.group_id=p_group;
    END IF;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        node_id,admin_boundary_id,admin_grant_subject_id,admin_grant_subject_kind,admin_grant_before,admin_grant_after)
    VALUES(actor.actor,actor.session_id,session_user,'ui','boundary_group_rotation','success',inet_client_addr(),actor.app_version,
        p_node,p_boundary,p_group,'group',selected.permissions,p_mask);
    status:='changed'; snapshot:=convert_to(p_publication->>'manifest','UTF8'); RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::jsonb,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea;
END
$rotate$;

REVOKE ALL ON FUNCTION wormhole_data.publish_boundary_rotation(uuid,jsonb,jsonb,jsonb),
    wormhole_api_v1.rotate_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.rotate_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)
    TO wh_{{TAG}}_user;
