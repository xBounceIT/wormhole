CREATE FUNCTION wormhole_data.group_member_rotation_scope(p_actor uuid,p_key uuid,p_version integer) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $scope$
DECLARE item record; purpose integer; doc jsonb; result jsonb:='[]'; count integer:=0;
BEGIN
    FOR item IN
        SELECT k.key_id,k.key_version,k.kind,k.owner_id,k.status,b.deleted,b.owner_user_id,m.body
        FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
        LEFT JOIN wormhole_data.boundaries b ON b.id=k.owner_id
        LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        WHERE (c.holder_key_id,c.holder_key_version)=(p_key,p_version)
        ORDER BY k.owner_id,k.kind,k.key_id,k.key_version LIMIT 4097
    LOOP
        count:=count+1;
        IF count>4096 THEN RAISE EXCEPTION 'Member rotation scope exceeds review limits' USING ERRCODE='WH020'; END IF;
        IF item.kind NOT IN ('boundary-view','boundary-secret') OR item.status<>'active' OR item.key_version>=2147483647
            OR item.body IS NULL OR item.deleted IS DISTINCT FROM false OR item.owner_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'Boundary copy must be reconciled before removing this member' USING ERRCODE='WH020';
        END IF;
        purpose:=CASE WHEN item.kind='boundary-view' THEN 1 ELSE 2 END;
        doc:=convert_from(item.body,'UTF8')::jsonb;
        IF doc->>'active' IS DISTINCT FROM 'true' OR doc->>'orgEscrow' IS DISTINCT FROM 'true'
            OR doc->>'previousView' IS NOT NULL OR doc->>'previousSecret' IS NOT NULL
            OR doc#>ARRAY[CASE WHEN purpose=1 THEN 'view' ELSE 'secret' END,'key'] IS DISTINCT FROM
                jsonb_build_object('id',item.key_id,'version',item.key_version)
            OR (wormhole_data.effective_boundary_permissions(p_actor,item.owner_id)&(16|purpose))<>(16|purpose)
            OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=item.owner_id) THEN
            RAISE EXCEPTION 'Boundary is unavailable for member rotation' USING ERRCODE='WH020';
        END IF;
        result:=result||jsonb_build_array(jsonb_build_object('boundaryId',item.owner_id,'purpose',purpose,
            'key',jsonb_build_object('id',item.key_id,'version',item.key_version)));
    END LOOP;
    RETURN result;
END
$scope$;

CREATE FUNCTION wormhole_api_v1.rotate_group_member(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_job uuid,p_group uuid,p_revision bigint,p_member uuid,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,roster bytea,manifest bytea,pending bigint,
    org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,
    recipient_id uuid,recipient_version integer,recipient_public bytea,recipient_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex' AS $member$
DECLARE actor record; team wormhole_data.groups; old wormhole_data.keys; job wormhole_data.group_member_rotation_jobs;
    previous jsonb; scope jsonb; remaining record; next_roster bytea; document bytea;
    signer record; recipient wormhole_data.keys; recipient_ref jsonb; next_raw text; next_doc jsonb;
    copy jsonb; item jsonb; recipients jsonb; binding jsonb; sealed jsonb; proof bytea;
    encapsulated bytea; wrapped bytea; position integer:=0;
BEGIN
    IF p_job IS NULL OR p_job='00000000-0000-0000-0000-000000000000'
        OR p_group IS NULL OR p_member IS NULL OR p_revision IS NULL OR p_revision<1 OR p_revision=9223372036854775807
        OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object'
            OR octet_length(p_publication::text)>131072)) THEN
        RAISE EXCEPTION 'Invalid member rotation request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    SELECT * INTO job FROM wormhole_data.group_member_rotation_jobs j WHERE j.id=p_job FOR SHARE NOWAIT;
    SELECT * INTO team FROM wormhole_data.groups g WHERE g.id=p_group FOR SHARE NOWAIT;
    IF NOT FOUND OR team.key_manifest IS NULL THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    previous:=convert_from(team.key_manifest,'UTF8')::jsonb;
    IF job.id IS NOT NULL THEN
        IF (job.group_id,job.removed_user_id,job.group_revision) IS DISTINCT FROM (p_group,p_member,p_revision)
            OR (p_review IS NOT NULL AND p_review<>job.review_digest)
            OR previous#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',job.key_id,'version',job.retired_version+1) THEN
            status:='stale'; RETURN NEXT; RETURN;
        END IF;
        status:='rotated'; manifest:=team.key_manifest;
        SELECT count(DISTINCT q.boundary_id) INTO pending FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job;
        RETURN NEXT; RETURN;
    END IF;
    IF team.row_version<>p_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF EXISTS(SELECT FROM wormhole_data.group_member_rotation_jobs j WHERE j.group_id=p_group AND NOT j.complete) THEN
        status:='rotation-pending'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=p_group AND m.user_id=p_member AND m.signature IS NULL) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO old FROM wormhole_data.keys k WHERE k.kind='group' AND k.owner_id=p_group AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((previous#>>'{key,key,id}')::uuid,(previous#>>'{key,key,version}')::integer)
        AND k.key_version<2147483647 AND k.public_key=decode(previous#>>'{key,public}','base64') FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((previous#>>'{recovery,id}')::uuid,(previous#>>'{recovery,version}')::integer)
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=((previous#>>'{signer,id}')::uuid,(previous#>>'{signer,version}')::integer)
        AND k.cert_revision=1 AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT remaining FROM wormhole_data.group_key_roster_after_removal(p_group,p_member);
    IF remaining.status NOT IN ('ready','no-members') THEN status:='incomplete'; RETURN NEXT; RETURN; END IF;
    next_roster:=coalesce(remaining.body,convert_to('[]','UTF8'));
    scope:=wormhole_data.group_member_rotation_scope(actor.actor,old.key_id,old.key_version);
    document:=convert_to(jsonb_build_object('jobId',p_job,'groupId',p_group,'groupRevision',p_revision::text,'memberId',p_member,
        'manifest',encode(team.key_manifest,'hex'),'rosterDigest',encode(sha256(next_roster),'hex'),'roots',scope)::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/member-rotation-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; roster:=next_roster; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT signer FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    IF jsonb_build_object('id',signer.org_key_id,'version',signer.org_key_version) IS DISTINCT FROM previous->'signer' THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; snapshot:=document; roster:=next_roster;
        org_key_id:=signer.org_key_id; org_key_version:=signer.org_key_version; enc:=signer.enc; ciphertext:=signer.ciphertext; signature:=signer.signature;
        recipient_id:=recipient.key_id; recipient_version:=recipient.key_version; recipient_public:=recipient.public_key; recipient_signature:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'member_rotation_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    next_raw:=p_publication->>'manifest';
    IF octet_length(next_raw) IS NULL OR octet_length(next_raw)>4096 OR jsonb_typeof(p_publication->'copies') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'Invalid member rotation publication' USING ERRCODE='22023';
    END IF;
    next_doc:=next_raw::jsonb;
    IF next_doc-ARRAY['groupRevision','rosterDigest','key','signature'] IS DISTINCT FROM previous-ARRAY['groupRevision','rosterDigest','key','signature']
        OR next_doc->'groupRevision' IS DISTINCT FROM to_jsonb(p_revision)
        OR next_doc->>'rosterDigest' IS DISTINCT FROM encode(wormhole_data.group_key_review(p_group,p_revision,next_roster),'base64')
        OR next_doc#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',old.key_id,'version',old.key_version+1)
        OR next_doc#>'{key,public}' IS NOT DISTINCT FROM previous#>'{key,public}'
        OR octet_length(decode(next_doc#>>'{key,public}','base64')) IS DISTINCT FROM 32
        OR octet_length(decode(next_doc->>'signature','base64')) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid replacement group manifest' USING ERRCODE='22023';
    END IF;
    recipients:=convert_from(next_roster,'UTF8')::jsonb||jsonb_build_array(jsonb_build_array(NULL,recipient.key_id,recipient.key_version::text));
    IF jsonb_array_length(p_publication->'copies')<>jsonb_array_length(recipients) THEN
        RAISE EXCEPTION 'Invalid group replacement copy count' USING ERRCODE='22023';
    END IF;
    UPDATE wormhole_data.keys k SET status='retired',row_version=row_version+1 WHERE (k.key_id,k.key_version)=(old.key_id,old.key_version);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
    VALUES(old.key_id,old.key_version+1,'group',p_group,2,decode(next_doc#>>'{key,public}','base64'));
    FOR item IN SELECT value FROM jsonb_array_elements(recipients) LOOP
        copy:=p_publication->'copies'->position; binding:=copy->'binding'; sealed:=copy->'envelope';
        recipient_ref:=jsonb_build_object('id',(item->>1)::uuid,'version',(item->>2)::integer);
        proof:=decode(copy->>'signature','base64');
        encapsulated:=decode(sealed->>'enc','base64'); wrapped:=decode(sealed->>'ciphertext','base64');
        IF binding->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR binding->'key' IS DISTINCT FROM next_doc#>'{key,key}'
            OR binding->'holder' IS DISTINCT FROM recipient_ref OR binding->'issuer' IS DISTINCT FROM previous->'signer'
            OR sealed->'formatVersion' IS DISTINCT FROM '1'::jsonb OR sealed->'suiteId' IS DISTINCT FROM '2'::jsonb
            OR octet_length(proof) IS DISTINCT FROM 64 OR octet_length(encapsulated) IS DISTINCT FROM 32 OR octet_length(wrapped) IS DISTINCT FROM 48 THEN
            RAISE EXCEPTION 'Invalid replacement group copy' USING ERRCODE='22023';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(old.key_id,old.key_version+1,(item->>1)::uuid,(item->>2)::integer,2,encapsulated,wrapped,signer.org_key_id,signer.org_key_version,proof);
        position:=position+1;
    END LOOP;
    DELETE FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(old.key_id,old.key_version);
    DELETE FROM wormhole_data.group_members m WHERE m.group_id=p_group AND m.user_id=p_member;
    manifest:=convert_to(next_raw,'UTF8');
    UPDATE wormhole_data.groups SET key_manifest=manifest,row_version=row_version+1 WHERE id=p_group;
    INSERT INTO wormhole_data.group_member_rotation_jobs(id,group_id,removed_user_id,group_revision,review_digest,key_id,retired_version,complete)
    VALUES(p_job,p_group,p_member,p_revision,p_review,old.key_id,old.key_version,jsonb_array_length(scope)=0);
    INSERT INTO wormhole_data.group_boundary_rotation_queue(job_id,boundary_id,purpose,root_id,root_version)
    SELECT p_job,(r.value->>'boundaryId')::uuid,(r.value->>'purpose')::integer,
        (r.value#>>'{key,id}')::uuid,(r.value#>>'{key,version}')::integer FROM jsonb_array_elements(scope) r;
    SELECT count(DISTINCT q.boundary_id) INTO pending FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,admin_group_id,admin_subject_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','group_member_rotation','success',inet_client_addr(),actor.app_version,p_group,p_member);
    status:='rotated'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bigint,NULL::uuid,NULL::integer,NULL::bytea,
        NULL::bytea,NULL::bytea,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea;
END
$member$;

REVOKE ALL ON FUNCTION wormhole_data.group_member_rotation_scope(uuid,uuid,integer),
    wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb)
    TO wh_{{TAG}}_user;
