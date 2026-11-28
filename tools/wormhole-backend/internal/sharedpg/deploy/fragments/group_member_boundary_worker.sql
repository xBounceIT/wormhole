CREATE FUNCTION wormhole_api_v1.group_member_rotation_status(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_group uuid,p_job uuid)
RETURNS TABLE(job_id uuid,pending bigint,next_boundary uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $job$
DECLARE actor record; item wormhole_data.group_member_rotation_jobs;
BEGIN
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    SELECT * INTO item FROM wormhole_data.group_member_rotation_jobs j
        WHERE j.group_id=p_group AND ((p_job IS NULL AND NOT j.complete) OR j.id=p_job) FOR SHARE NOWAIT;
    IF NOT FOUND THEN RETURN; END IF;
    job_id:=item.id;
    SELECT count(DISTINCT q.boundary_id) INTO pending FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=item.id;
    SELECT q.boundary_id INTO next_boundary FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=item.id
        GROUP BY q.boundary_id
        HAVING (wormhole_data.effective_boundary_permissions(actor.actor,q.boundary_id)&(16|bit_or(q.purpose)))=(16|bit_or(q.purpose))
        ORDER BY q.boundary_id LIMIT 1;
    RETURN NEXT;
END
$job$;

{{MEMBER_BOUNDARY_WORKER_CREATE}} wormhole_api_v1.rotate_member_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_job uuid,p_boundary uuid,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,graph jsonb,sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,org_public bytea,org_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex' AS $worker$
DECLARE actor record; meta record; job wormhole_data.group_member_rotation_jobs; boundary wormhole_data.boundaries;
    team wormhole_data.groups; selected wormhole_data.boundary_manifests; old jsonb; updated_group jsonb; recipient wormhole_data.keys;
    mask integer; next_graph jsonb; document bytea; org_signing record; org_encryption record;
{{MEMBER_BOUNDARY_EXTRA_LOCALS}}
BEGIN
    IF p_job IS NULL OR p_boundary IS NULL OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object'
            OR octet_length(p_publication::text)>16777216)) THEN
        RAISE EXCEPTION 'Invalid member boundary rotation request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    SELECT * INTO job FROM wormhole_data.group_member_rotation_jobs j WHERE j.id=p_job FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO boundary FROM wormhole_data.boundaries b WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE NOWAIT;
    IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&16)<>16 THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT bit_or(q.purpose) INTO mask FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job AND q.boundary_id=p_boundary;
    IF mask IS NULL THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    IF (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&mask)<>mask THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT team FROM wormhole_data.groups g WHERE g.id=job.group_id FOR SHARE NOWAIT;
    updated_group:=convert_from(team.key_manifest,'UTF8')::jsonb;
    IF updated_group#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',job.key_id,'version',{{MEMBER_BOUNDARY_GENERATION}})
        OR EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=job.group_id AND m.user_id=job.removed_user_id) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO selected FROM wormhole_data.boundary_manifests b WHERE b.boundary_id=p_boundary FOR SHARE NOWAIT;
    IF NOT FOUND OR selected.version=9223372036854775807 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    old:=convert_from(selected.body,'UTF8')::jsonb;
    IF old->>'active' IS DISTINCT FROM 'true' OR old->>'orgEscrow' IS DISTINCT FROM 'true'
        OR old->>'previousView' IS NOT NULL OR old->>'previousSecret' IS NOT NULL OR old->'signer' IS DISTINCT FROM updated_group->'signer'
        OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job AND q.boundary_id=p_boundary
            AND old#>ARRAY[CASE WHEN q.purpose=1 THEN 'view' ELSE 'secret' END,'key'] IS DISTINCT FROM
                jsonb_build_object('id',q.root_id,'version',q.root_version)) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((updated_group#>>'{recovery,id}')::uuid,(updated_group#>>'{recovery,version}')::integer)
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(selected.signer_key_id,selected.signer_key_version)
        AND k.cert_revision=1 AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton;
{{MEMBER_BOUNDARY_GRAPH}}
    IF octet_length(next_graph::text)>50331648 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    document:=convert_to(jsonb_build_object('jobId',p_job,'boundaryId',p_boundary,'groupId',job.group_id,
        'groupRevision',({{MEMBER_BOUNDARY_REVISION}})::text,'memberId',job.removed_user_id,'affected',mask,'epoch',meta.epoch::text,'changeSeq',meta.change_seq::text,
        'boundary',encode(selected.body,'hex'),'group',encode(team.key_manifest,'hex'),
        'graphDigest',encode(sha256(convert_to(next_graph::text,'UTF8')),'hex'))::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/member-boundary-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    IF (org_signing.org_key_id,org_signing.org_key_version)<>(selected.signer_key_id,selected.signer_key_version)
        OR (org_encryption.org_key_id,org_encryption.org_key_version)<>(recipient.key_id,recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; snapshot:=document; graph:=next_graph;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version;
        org_enc:=org_encryption.enc; org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'member_boundary_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    PERFORM wormhole_data.publish_boundary_rotation(p_boundary,old,next_graph,p_publication);
{{MEMBER_BOUNDARY_FINISH}}
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        admin_boundary_id,admin_group_id,admin_subject_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','member_boundary_rotation','success',inet_client_addr(),
        actor.app_version,p_boundary,job.group_id,job.removed_user_id);
    status:='changed'; snapshot:=convert_to(p_publication->>'manifest','UTF8'); RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::jsonb,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea;
END
$worker$;

REVOKE ALL ON FUNCTION wormhole_api_v1.group_member_rotation_status(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid),
    wormhole_api_v1.rotate_member_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.group_member_rotation_status(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid),
    wormhole_api_v1.rotate_member_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bytea,jsonb) TO wh_{{TAG}}_user;
