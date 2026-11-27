-- Version 69: reconcile a changed certified roster while boundary rotation is pending.
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
        AND role_tag='{{TAG}}' AND schema_version=68 FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000'; END IF;
END
$guard$;

-- NULL retains the original generation and revision inferred by schemas 66–68.
-- Keep the initial receipt fields intact when later roster reviews supersede it.
ALTER TABLE wormhole_data.group_member_rotation_jobs
    ADD COLUMN replacement_version integer,
    ADD COLUMN replacement_revision bigint,
    ADD CHECK ((replacement_version IS NULL AND replacement_revision IS NULL) OR
        (replacement_version IS NOT NULL AND replacement_revision IS NOT NULL
            AND replacement_version>retired_version+1 AND replacement_revision>group_revision)),
    ADD FOREIGN KEY(key_id,replacement_version) REFERENCES wormhole_data.keys(key_id,key_version);
ALTER TABLE wormhole_data.group_boundary_rotation_queue
    ADD COLUMN holder_version integer CHECK(holder_version BETWEEN 1 AND 2147483646),
    DROP CONSTRAINT group_boundary_rotation_queue_root_id_root_version_key;
CREATE INDEX group_boundary_rotation_by_root ON wormhole_data.group_boundary_rotation_queue(root_id,root_version);

CREATE OR REPLACE FUNCTION wormhole_data.group_rotation_queue_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $valid$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.group_member_rotation_jobs j
        JOIN wormhole_data.groups g ON g.id=j.group_id
        JOIN wormhole_data.keys old ON (old.key_id,old.key_version)=(j.key_id,j.retired_version)
        WHERE old.owner_id IS DISTINCT FROM j.group_id OR old.kind<>'group' OR old.status<>'retired'
          OR EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(j.key_id,j.retired_version))
          OR j.complete IS DISTINCT FROM (NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=j.id))
          OR (NOT j.complete AND (
              (convert_from(g.key_manifest,'UTF8')::jsonb#>'{key,key}') IS DISTINCT FROM
                  jsonb_build_object('id',j.key_id,'version',COALESCE(j.replacement_version,j.retired_version+1))
              OR (convert_from(g.key_manifest,'UTF8')::jsonb->>'groupRevision') IS DISTINCT FROM
                  COALESCE(j.replacement_revision,j.group_revision)::text
              OR EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=j.group_id AND m.user_id=j.removed_user_id)
          ))
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.group_boundary_rotation_queue q JOIN wormhole_data.group_member_rotation_jobs j ON j.id=q.job_id
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(q.root_id,q.root_version)
        WHERE k.owner_id IS DISTINCT FROM q.boundary_id OR k.status<>'active'
          OR k.kind<>CASE WHEN q.purpose=1 THEN 'boundary-view' ELSE 'boundary-secret' END
          OR (q.holder_version IS NOT NULL AND (q.holder_version<=j.retired_version OR
              j.replacement_version IS NULL OR q.holder_version>=j.replacement_version))
          OR NOT EXISTS(SELECT FROM wormhole_data.keys h JOIN wormhole_data.key_copies c
              ON (c.holder_key_id,c.holder_key_version)=(h.key_id,h.key_version)
              WHERE (h.key_id,h.key_version,c.key_id,c.key_version)=(j.key_id,COALESCE(q.holder_version,j.retired_version),q.root_id,q.root_version)
                AND h.owner_id=j.group_id AND h.kind='group' AND h.status='retired'
                AND NOT EXISTS(SELECT FROM wormhole_data.key_copies private_copy
                    WHERE (private_copy.key_id,private_copy.key_version)=(h.key_id,h.key_version)))
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
        WHERE k.kind='group' AND k.status='retired'
          AND NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q JOIN wormhole_data.group_member_rotation_jobs j ON j.id=q.job_id
              WHERE (q.root_id,q.root_version,j.key_id,COALESCE(q.holder_version,j.retired_version))=
                  (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version))
    )
$valid$;

CREATE FUNCTION wormhole_data.rotation_job_roster(p_job wormhole_data.group_member_rotation_jobs)
RETURNS TABLE(status text,body bytea,manifest bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $roster$
DECLARE document jsonb; current_roster record; revision bigint:=COALESCE(p_job.replacement_revision,p_job.group_revision);
BEGIN
    SELECT g.key_manifest INTO STRICT manifest FROM wormhole_data.groups g WHERE g.id=p_job.group_id FOR SHARE NOWAIT;
    document:=convert_from(manifest,'UTF8')::jsonb;
    IF document#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',p_job.key_id,'version',COALESCE(p_job.replacement_version,p_job.retired_version+1))
        OR document->>'groupRevision' IS DISTINCT FROM revision::text
        OR EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=p_job.group_id AND m.user_id=p_job.removed_user_id) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT current_roster FROM wormhole_data.group_key_roster(p_job.group_id);
    IF current_roster.status NOT IN ('ready','no-members') THEN status:='incomplete'; RETURN NEXT; RETURN; END IF;
    body:=COALESCE(current_roster.body,convert_to('[]','UTF8'));
    status:=CASE WHEN document->>'rosterDigest' IS DISTINCT FROM
        encode(wormhole_data.group_key_review(p_job.group_id,revision,body),'base64') THEN 'changed' ELSE current_roster.status END;
    RETURN NEXT;
END
$roster$;

-- A root can have been held by several groups awaiting a replacement. Publish
-- one new root with every current, certified recipient, then finish that root
-- for all affected jobs. A changed roster is reported before any writes.
CREATE FUNCTION wormhole_data.member_rotation_joint_graph(p_boundary uuid,p_group uuid,p_mask integer,p_old jsonb,
    p_org uuid,p_org_version integer,p_epoch bigint,p_sequence bigint) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $graph$
DECLARE queued record; proof record; root jsonb; purpose integer; doc jsonb; key_ref jsonb;
    extra jsonb:='{"1":[],"2":[]}'; result jsonb:='[]';
BEGIN
    -- Another job may need to requeue an already-rotated root presently held
    -- by that group's active generation. Surface its review before building
    -- the ordinary retained-recipient graph, which would refuse that holder.
    FOR queued IN
        SELECT DISTINCT j AS job FROM wormhole_data.group_boundary_rotation_queue q
        JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(q.root_id,q.root_version)
        JOIN wormhole_data.group_member_rotation_jobs j
            ON (c.holder_key_id,c.holder_key_version)=(j.key_id,COALESCE(j.replacement_version,j.retired_version+1))
        WHERE q.boundary_id=p_boundary AND (q.purpose&p_mask)<>0 AND NOT j.complete
    LOOP
        SELECT * INTO STRICT proof FROM wormhole_data.rotation_job_roster(queued.job);
        IF proof.status NOT IN ('ready','no-members') THEN RETURN NULL; END IF;
    END LOOP;
    FOR queued IN
        SELECT j AS job,q.purpose,q.root_id,q.root_version,g.permissions
        FROM wormhole_data.group_boundary_rotation_queue q JOIN wormhole_data.group_member_rotation_jobs j ON j.id=q.job_id
        LEFT JOIN wormhole_data.boundary_grants g ON g.boundary_id=q.boundary_id AND g.group_id=j.group_id
        WHERE q.boundary_id=p_boundary AND (q.purpose&p_mask)<>0
        ORDER BY q.purpose,j.group_id FOR SHARE OF j,q NOWAIT
    LOOP
        key_ref:=p_old#>ARRAY[CASE WHEN queued.purpose=1 THEN 'view' ELSE 'secret' END,'key'];
        IF key_ref IS DISTINCT FROM jsonb_build_object('id',queued.root_id,'version',queued.root_version) THEN
            RAISE EXCEPTION 'Boundary rotation roots changed' USING ERRCODE='WH013';
        END IF;
        SELECT * INTO STRICT proof FROM wormhole_data.rotation_job_roster(queued.job);
        IF proof.status NOT IN ('ready','no-members') THEN RETURN NULL; END IF;
        IF proof.status='ready' AND (COALESCE(queued.permissions,0)&queued.purpose)<>0 THEN
            doc:=convert_from(proof.manifest,'UTF8')::jsonb;
            extra:=jsonb_set(extra,ARRAY[queued.purpose::text],(extra->queued.purpose::text)||jsonb_build_array(jsonb_build_object(
                'kind','group','subject',(queued.job).group_id,'key',doc#>'{key,key}',
                'manifest',encode(proof.manifest,'hex'),'proof',convert_from(proof.body,'UTF8'))));
        END IF;
    END LOOP;
    FOR root IN SELECT value FROM jsonb_array_elements(wormhole_data.boundary_rotation_graph(p_boundary,p_group,p_mask,p_old,
        p_org,p_org_version,p_epoch,p_sequence))
    LOOP
        purpose:=CASE WHEN root->>'purpose'='view' THEN 1 ELSE 2 END;
        root:=jsonb_set(root,'{recipients}',(root->'recipients')||(extra->purpose::text));
        IF jsonb_array_length(root->'recipients')>1024 THEN
            RAISE EXCEPTION 'Boundary rotation recipient set is too large' USING ERRCODE='WH020';
        END IF;
        result:=result||jsonb_build_array(root);
    END LOOP;
    RETURN result;
END
$graph$;

CREATE FUNCTION wormhole_api_v1.reconcile_group_member_rotation(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_group uuid,p_job uuid,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,roster bytea,manifest bytea,org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,
    recipient_id uuid,recipient_version integer,recipient_public bytea,recipient_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex'
AS $reconcile$
DECLARE actor record; job wormhole_data.group_member_rotation_jobs; related wormhole_data.group_member_rotation_jobs;
    team wormhole_data.groups; old wormhole_data.keys;
    proof record; root record; doc jsonb; previous jsonb; next_raw text; next_doc jsonb; root_ref jsonb;
    pending jsonb; additional jsonb:='[]'; document bytea; boundary_count integer; position integer:=0;
    recipient wormhole_data.keys; signer record; issuer jsonb; row jsonb;
BEGIN
    IF p_group IS NULL OR p_job IS NULL OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object'
            OR octet_length(p_publication::text)>131072)) THEN
        RAISE EXCEPTION 'Invalid rotation reconciliation request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    PERFORM FROM wormhole_data.group_member_rotation_jobs j WHERE j.id=p_job AND j.group_id=p_group AND NOT j.complete FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    -- Prefer the requested group. A job sharing one of its queued roots can also
    -- require a roster review before either job can publish that root.
    FOR related IN
        SELECT j.* FROM wormhole_data.group_member_rotation_jobs j WHERE NOT j.complete AND
          (j.id=p_job OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue requested
              JOIN wormhole_data.group_boundary_rotation_queue sibling USING(root_id,root_version)
              WHERE requested.job_id=p_job AND sibling.job_id=j.id)
            OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue requested
              JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(requested.root_id,requested.root_version)
              WHERE requested.job_id=p_job AND (c.holder_key_id,c.holder_key_version)=
                  (j.key_id,COALESCE(j.replacement_version,j.retired_version+1))))
        ORDER BY (j.id=p_job) DESC,j.group_id FOR SHARE NOWAIT
    LOOP
        SELECT * INTO STRICT proof FROM wormhole_data.rotation_job_roster(related);
        IF proof.status IN ('unavailable','incomplete') THEN status:=proof.status; RETURN NEXT; RETURN; END IF;
        IF proof.status='changed' THEN
            SELECT * INTO job FROM wormhole_data.group_member_rotation_jobs j WHERE j.id=related.id;
            EXIT;
        END IF;
    END LOOP;
    IF job.id IS NULL THEN status:='unchanged'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT team FROM wormhole_data.groups g WHERE g.id=job.group_id FOR SHARE NOWAIT;
    IF team.row_version>=9223372036854775807 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    previous:=convert_from(proof.manifest,'UTF8')::jsonb; issuer:=previous->'signer';
    SELECT * INTO old FROM wormhole_data.keys k WHERE (k.key_id,k.key_version)=(job.key_id,COALESCE(job.replacement_version,job.retired_version+1))
        AND k.kind='group' AND k.owner_id=job.group_id AND k.status='active' AND k.suite=2
        AND k.key_version<2147483647 AND k.public_key=decode(previous#>>'{key,public}','base64') FOR SHARE NOWAIT;
    IF NOT FOUND OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=job.id
        AND (wormhole_data.effective_boundary_permissions(actor.actor,q.boundary_id)&(16|q.purpose))<>(16|q.purpose)) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT jsonb_agg(jsonb_build_object('boundaryId',q.boundary_id,'purpose',q.purpose,'key',jsonb_build_object('id',q.root_id,'version',q.root_version))
        ORDER BY q.boundary_id,q.purpose) INTO STRICT pending FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=job.id;
    IF pending IS NULL THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    FOR root IN
        SELECT k.key_id,k.key_version,k.kind,k.owner_id,k.status,b.deleted,b.owner_user_id,m.body
        FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
        LEFT JOIN wormhole_data.boundaries b ON b.id=k.owner_id LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        WHERE (c.holder_key_id,c.holder_key_version)=(old.key_id,old.key_version)
        ORDER BY k.owner_id,k.kind,k.key_id,k.key_version LIMIT 4097
    LOOP
        IF jsonb_array_length(additional)>=4096 OR root.kind NOT IN ('boundary-view','boundary-secret') OR root.status<>'active'
            OR root.key_version>=2147483647 OR root.body IS NULL OR root.deleted IS DISTINCT FROM false OR root.owner_user_id IS NOT NULL THEN
            status:='unavailable'; RETURN NEXT; RETURN;
        END IF;
        position:=CASE WHEN root.kind='boundary-view' THEN 1 ELSE 2 END;
        doc:=convert_from(root.body,'UTF8')::jsonb;
        root_ref:=jsonb_build_object('id',root.key_id,'version',root.key_version);
        IF doc->>'active' IS DISTINCT FROM 'true' OR doc->>'orgEscrow' IS DISTINCT FROM 'true'
            OR doc->>'previousView' IS NOT NULL OR doc->>'previousSecret' IS NOT NULL OR doc->'signer' IS DISTINCT FROM issuer
            OR doc#>ARRAY[CASE WHEN position=1 THEN 'view' ELSE 'secret' END,'key'] IS DISTINCT FROM root_ref
            OR (wormhole_data.effective_boundary_permissions(actor.actor,root.owner_id)&(16|position))<>(16|position)
            OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=job.id AND q.boundary_id=root.owner_id AND q.purpose=position) THEN
            status:='unavailable'; RETURN NEXT; RETURN;
        END IF;
        additional:=additional||jsonb_build_array(jsonb_build_object('boundaryId',root.owner_id,'purpose',position,'key',root_ref));
    END LOOP;
    SELECT count(DISTINCT (value->>'boundaryId')::uuid) INTO boundary_count FROM jsonb_array_elements(pending||additional);
    IF jsonb_array_length(pending||additional)>4096 THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    document:=convert_to(jsonb_build_object('requestJobId',p_job,'requestGroupId',p_group,'jobId',job.id,'groupId',job.group_id,
        'groupName',team.name,'groupRevision',team.row_version::text,'removedMemberId',job.removed_user_id,
        'previous',encode(proof.manifest,'hex'),'rosterDigest',encode(sha256(proof.body),'hex'),
        'pending',pending,'additional',additional,'boundaries',boundary_count)::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/rotation-reconciliation-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; roster:=proof.body; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT signer FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2
        AND (k.key_id,k.key_version)=((previous#>>'{recovery,id}')::uuid,(previous#>>'{recovery,version}')::integer)
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(signer.org_key_id,signer.org_key_version)
        AND k.cert_revision=1 AND octet_length(k.public_key)=32 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND OR issuer IS DISTINCT FROM jsonb_build_object('id',signer.org_key_id,'version',signer.org_key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    IF p_publication IS NULL THEN
        status:='ready'; snapshot:=document; roster:=proof.body;
        org_key_id:=signer.org_key_id; org_key_version:=signer.org_key_version; enc:=signer.enc; ciphertext:=signer.ciphertext; signature:=signer.signature;
        recipient_id:=recipient.key_id; recipient_version:=recipient.key_version; recipient_public:=recipient.public_key; recipient_signature:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'member_reconciliation_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    next_raw:=p_publication->>'manifest'; next_doc:=next_raw::jsonb;
    IF octet_length(next_raw) IS NULL OR octet_length(next_raw)>4096 OR jsonb_typeof(p_publication->'copies') IS DISTINCT FROM 'array'
        OR jsonb_array_length(p_publication->'copies')<>jsonb_array_length(convert_from(proof.body,'UTF8')::jsonb)+1
        OR next_doc-ARRAY['groupRevision','rosterDigest','key','signature'] IS DISTINCT FROM previous-ARRAY['groupRevision','rosterDigest','key','signature']
        OR next_doc->'groupRevision' IS DISTINCT FROM to_jsonb(team.row_version)
        OR next_doc->>'rosterDigest' IS DISTINCT FROM encode(wormhole_data.group_key_review(job.group_id,team.row_version,proof.body),'base64')
        OR next_doc#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',old.key_id,'version',old.key_version+1)
        OR next_doc#>'{key,public}' IS NOT DISTINCT FROM previous#>'{key,public}'
        OR octet_length(decode(next_doc#>>'{key,public}','base64')) IS DISTINCT FROM 32
        OR octet_length(decode(next_doc->>'signature','base64')) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid reconciled group manifest' USING ERRCODE='22023';
    END IF;
    UPDATE wormhole_data.keys k SET status='retired',row_version=row_version+1 WHERE (k.key_id,k.key_version)=(old.key_id,old.key_version);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
    VALUES(old.key_id,old.key_version+1,'group',job.group_id,2,decode(next_doc#>>'{key,public}','base64'));
    position:=0;
    FOR row IN SELECT value FROM jsonb_array_elements(convert_from(proof.body,'UTF8')::jsonb||jsonb_build_array(jsonb_build_array(NULL,recipient.key_id,recipient.key_version::text))) LOOP
        PERFORM wormhole_data.insert_member_addition_copy(p_publication->'copies'->position,next_doc#>'{key,key}',
            jsonb_build_object('id',(row->>1)::uuid,'version',(row->>2)::integer),issuer);
        position:=position+1;
    END LOOP;
    DELETE FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(old.key_id,old.key_version);
    INSERT INTO wormhole_data.group_boundary_rotation_queue(job_id,boundary_id,purpose,root_id,root_version,holder_version)
    SELECT job.id,(value->>'boundaryId')::uuid,(value->>'purpose')::integer,(value#>>'{key,id}')::uuid,(value#>>'{key,version}')::integer,
        old.key_version FROM jsonb_array_elements(additional);
    manifest:=convert_to(next_raw,'UTF8');
    UPDATE wormhole_data.groups SET key_manifest=manifest,row_version=row_version+1 WHERE id=job.group_id;
    UPDATE wormhole_data.group_member_rotation_jobs j SET replacement_version=old.key_version+1,replacement_revision=team.row_version WHERE j.id=job.id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,admin_group_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','group_member_reconciliation','success',inet_client_addr(),actor.app_version,job.group_id);
    status:='reconciled'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::bytea,NULL::bytea,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,
        NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea;
END
$reconcile$;

REVOKE ALL ON FUNCTION wormhole_data.rotation_job_roster(wormhole_data.group_member_rotation_jobs),
    wormhole_data.member_rotation_joint_graph(uuid,uuid,integer,jsonb,uuid,integer,bigint,bigint),
    wormhole_api_v1.reconcile_group_member_rotation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.reconcile_group_member_rotation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bytea,jsonb)
    TO wh_{{TAG}}_user;

{{MEMBER_BOUNDARY_WORKER}}
{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=69 WHERE singleton;
COMMIT;
