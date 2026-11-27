-- Version 68: certified membership expansion and transfer of current boundary wraps.
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
        AND role_tag='{{TAG}}' AND schema_version=67 FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000'; END IF;
END
$guard$;

-- Atomic addition receipts are operational data, like import receipts. Recovery
-- archives contain the committed memberships, generations and copies themselves.
CREATE TABLE wormhole_data.group_member_additions (
    id uuid PRIMARY KEY,
    group_id uuid NOT NULL REFERENCES wormhole_data.groups(id),
    member_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    group_revision bigint NOT NULL CHECK(group_revision>0),
    review_digest bytea NOT NULL CHECK(octet_length(review_digest)=32),
    key_id uuid NOT NULL,
    key_version integer NOT NULL,
    FOREIGN KEY(key_id,key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);

CREATE FUNCTION wormhole_data.member_addition_scope(p_actor uuid,p_group uuid,p_old wormhole_data.keys,p_empty boolean,p_issuer jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $scope$
DECLARE item record; body jsonb; refs jsonb; key_ref jsonb; bit integer; count integer:=0;
    results jsonb:='[]'; wrapped_count integer:=0;
BEGIN
    FOR item IN
        SELECT g.boundary_id,g.permissions,g.row_version,g.signature,b.id,b.deleted,b.owner_user_id,m.body
        FROM wormhole_data.boundary_grants g LEFT JOIN wormhole_data.boundaries b ON b.id=g.boundary_id
        LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=g.boundary_id
        WHERE g.group_id=p_group AND (g.permissions&3)<>0 ORDER BY g.boundary_id LIMIT 4097 FOR SHARE OF g NOWAIT
    LOOP
        count:=count+1;
        IF count>4096 OR item.body IS NULL OR octet_length(item.body)>8192 OR item.deleted IS DISTINCT FROM false
            OR item.owner_user_id IS NOT NULL OR item.signature IS NOT NULL
            OR (wormhole_data.effective_boundary_permissions(p_actor,item.boundary_id)&(16|(item.permissions&3)))<>(16|(item.permissions&3))
            OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=item.boundary_id) THEN
            RAISE EXCEPTION 'Group boundary is unavailable for member addition' USING ERRCODE='WH020';
        END IF;
        body:=convert_from(item.body,'UTF8')::jsonb;
        IF body->>'active' IS DISTINCT FROM 'true' OR body->>'orgEscrow' IS DISTINCT FROM 'true'
            OR body->>'previousView' IS NOT NULL OR body->>'previousSecret' IS NOT NULL OR body->'signer' IS DISTINCT FROM p_issuer THEN
            RAISE EXCEPTION 'Group boundary is unavailable for member addition' USING ERRCODE='WH020';
        END IF;
        refs:='[]';
        FOR bit IN 0..1 LOOP
            IF (item.permissions&(1<<bit))=0 THEN CONTINUE; END IF;
            key_ref:=body#>ARRAY[CASE WHEN bit=0 THEN 'view' ELSE 'secret' END,'key'];
            IF NOT EXISTS(SELECT FROM wormhole_data.keys k
                WHERE (k.key_id,k.key_version)=((key_ref->>'id')::uuid,(key_ref->>'version')::integer)
                  AND k.kind=CASE WHEN bit=0 THEN 'boundary-view' ELSE 'boundary-secret' END
                  AND k.owner_id=item.boundary_id AND k.status='active' AND k.suite=2)
                OR EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)=
                    ((key_ref->>'id')::uuid,(key_ref->>'version')::integer,p_old.key_id,p_old.key_version))=p_empty THEN
                RAISE EXCEPTION 'Group boundary copies need reconciliation' USING ERRCODE='WH020';
            END IF;
            refs:=refs||jsonb_build_array(key_ref);
            IF NOT p_empty THEN wrapped_count:=wrapped_count+1; END IF;
        END LOOP;
        results:=results||jsonb_build_array(jsonb_build_object('id',item.boundary_id,'grantRevision',item.row_version::text,
            'mask',item.permissions&3,'manifest',encode(item.body,'hex'),'keys',refs));
        IF octet_length(results::text)>8388608 THEN RAISE EXCEPTION 'Group scope exceeds review limit' USING ERRCODE='WH020'; END IF;
    END LOOP;
    IF wrapped_count<>(SELECT count(*) FROM wormhole_data.key_copies c WHERE (c.holder_key_id,c.holder_key_version)=(p_old.key_id,p_old.key_version)) THEN
        RAISE EXCEPTION 'Group holds unreviewed boundary copies' USING ERRCODE='WH020';
    END IF;
    RETURN results;
END
$scope$;

CREATE FUNCTION wormhole_data.insert_member_addition_copy(p_copy jsonb,p_key jsonb,p_holder jsonb,p_issuer jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $copy$
DECLARE b jsonb:=p_copy->'binding'; e jsonb:=p_copy->'envelope'; proof bytea; enc bytea; ciphertext bytea;
BEGIN
    proof:=decode(p_copy->>'signature','base64'); enc:=decode(e->>'enc','base64'); ciphertext:=decode(e->>'ciphertext','base64');
    IF b->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR b->'key' IS DISTINCT FROM p_key
        OR b->'holder' IS DISTINCT FROM p_holder OR b->'issuer' IS DISTINCT FROM p_issuer
        OR e->>'formatVersion' IS DISTINCT FROM '1' OR e->>'suiteId' IS DISTINCT FROM '2'
        OR octet_length(proof) IS DISTINCT FROM 64 OR octet_length(enc) IS DISTINCT FROM 32 OR octet_length(ciphertext) IS DISTINCT FROM 48 THEN
        RAISE EXCEPTION 'Invalid member addition copy' USING ERRCODE='22023';
    END IF;
    INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,issuer_key_id,issuer_key_version,suite,enc,ciphertext,signature)
    VALUES((p_key->>'id')::uuid,(p_key->>'version')::integer,(p_holder->>'id')::uuid,(p_holder->>'version')::integer,
        (p_issuer->>'id')::uuid,(p_issuer->>'version')::integer,2,enc,ciphertext,proof);
END
$copy$;

CREATE FUNCTION wormhole_api_v1.add_keyed_group_member(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_request uuid,p_group uuid,p_revision bigint,p_login text,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,roster bytea,manifest bytea,escrow jsonb,
    sign_id uuid,sign_version integer,sign_enc bytea,sign_ciphertext bytea,sign_proof bytea,
    org_id uuid,org_version integer,org_enc bytea,org_ciphertext bytea,org_proof bytea,org_public bytea,org_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='30s' SET bytea_output='hex' AS $add$
DECLARE actor record; team wormhole_data.groups; old wormhole_data.keys; receipt wormhole_data.group_member_additions; subject uuid;
    previous jsonb; current_roster record; candidate jsonb; next_roster bytea; scope jsonb; document bytea; meta record;
    issuer jsonb; org_signing record; org_encryption record; recipient wormhole_data.keys; next_raw text; next_doc jsonb;
    item jsonb; ref jsonb; refs jsonb; copy_row record; position integer:=0;
BEGIN
    IF p_request IS NULL OR p_request='00000000-0000-0000-0000-000000000000' OR p_group IS NULL OR p_revision IS NULL
        OR p_revision<1 OR p_revision>=9223372036854775807 OR octet_length(p_login) IS NULL OR octet_length(p_login) NOT BETWEEN 1 AND 256
        OR p_login~'[[:cntrl:]]' OR (p_review IS NOT NULL AND octet_length(p_review)<>32)
        OR (p_publication IS NOT NULL AND (p_review IS NULL OR jsonb_typeof(p_publication) IS DISTINCT FROM 'object'
            OR octet_length(p_publication::text)>8388608)) THEN
        RAISE EXCEPTION 'Invalid member addition request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_publication IS NOT NULL);
    SELECT u.id INTO subject FROM wormhole_data.users u WHERE u.login_name=p_login AND u.login_name COLLATE "C"=p_login
        AND NOT u.disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='account-unavailable'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO team FROM wormhole_data.groups g WHERE g.id=p_group FOR SHARE NOWAIT;
    IF NOT FOUND OR team.key_manifest IS NULL THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    previous:=convert_from(team.key_manifest,'UTF8')::jsonb;
    SELECT * INTO receipt FROM wormhole_data.group_member_additions r WHERE r.id=p_request FOR SHARE NOWAIT;
    IF FOUND THEN
        IF (receipt.group_id,receipt.member_id,receipt.group_revision) IS DISTINCT FROM (p_group,subject,p_revision)
            OR (p_review IS NOT NULL AND p_review<>receipt.review_digest)
            OR previous#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',receipt.key_id,'version',receipt.key_version) THEN
            status:='stale'; RETURN NEXT; RETURN;
        END IF;
        status:='added'; manifest:=team.key_manifest; RETURN NEXT; RETURN;
    END IF;
    IF team.row_version<>p_revision THEN status:='stale'; RETURN NEXT; RETURN; END IF;
    IF EXISTS(SELECT FROM wormhole_data.group_member_rotation_jobs j WHERE j.group_id=p_group AND NOT j.complete) THEN
        status:='rotation-pending'; RETURN NEXT; RETURN;
    END IF;
    IF EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=p_group AND m.user_id=subject) THEN
        status:='unchanged'; RETURN NEXT; RETURN;
    END IF;
    IF EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=p_group AND m.signature IS NOT NULL) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT current_roster FROM wormhole_data.group_key_roster(p_group);
    IF current_roster.status NOT IN ('ready','no-members') OR previous->>'rosterDigest' IS DISTINCT FROM
        encode(wormhole_data.group_key_review(p_group,(previous->>'groupRevision')::bigint,coalesce(current_roster.body,convert_to('[]','UTF8'))),'base64') THEN
        status:='incomplete'; RETURN NEXT; RETURN;
    END IF;
    SELECT jsonb_build_array(e.user_id,e.encryption_key_id,e.encryption_key_version::text,
        encode(s.signed_state,'hex'),encode(e.certificate,'hex')) INTO candidate
    FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_states s USING(user_id)
    JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.encryption_key_id,e.encryption_key_version)
    WHERE e.user_id=subject AND k.kind='user-enc' AND k.owner_id=subject AND k.status='active' AND k.suite=2
        AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE OF e,s,k NOWAIT;
    IF NOT FOUND OR jsonb_array_length(coalesce(convert_from(current_roster.body,'UTF8')::jsonb,'[]'::jsonb))>=64 THEN
        status:='incomplete'; RETURN NEXT; RETURN;
    END IF;
    SELECT convert_to(jsonb_agg(value ORDER BY (value->>0)::uuid)::text,'UTF8') INTO next_roster
        FROM jsonb_array_elements(coalesce(convert_from(current_roster.body,'UTF8')::jsonb,'[]'::jsonb)||jsonb_build_array(candidate));
    IF octet_length(next_roster)>3145728 THEN status:='incomplete'; RETURN NEXT; RETURN; END IF;
    SELECT * INTO old FROM wormhole_data.keys k
        WHERE (k.key_id,k.key_version)=((previous#>>'{key,key,id}')::uuid,(previous#>>'{key,key,version}')::integer)
        AND k.kind='group' AND k.owner_id=p_group AND k.status='active' AND k.suite=2
        AND k.key_version<2147483647 AND k.public_key=decode(previous#>>'{key,public}','base64') FOR SHARE NOWAIT;
    IF NOT FOUND THEN status:='unavailable'; RETURN NEXT; RETURN; END IF;
    issuer:=previous->'signer';
    scope:=wormhole_data.member_addition_scope(actor.actor,p_group,old,current_roster.status='no-members',issuer);
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE singleton;
    document:=convert_to(jsonb_build_object('jobId',p_request,'groupId',p_group,'groupRevision',p_revision::text,'memberId',subject,
        'epoch',meta.epoch::text,'changeSeq',meta.change_seq::text,'previous',encode(team.key_manifest,'hex'),
        'priorRoster',coalesce(convert_from(current_roster.body,'UTF8'),'[]'),'rosterDigest',encode(sha256(next_roster),'hex'),'boundaries',scope)::text,'UTF8');
    IF p_review IS NOT NULL AND p_review<>sha256(convert_to('wormhole/v1/member-addition-review:','UTF8')||document) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF p_review IS NULL THEN status:='ready'; snapshot:=document; roster:=next_roster; RETURN NEXT; RETURN; END IF;
    SELECT * INTO STRICT org_signing FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    SELECT * INTO STRICT org_encryption FROM wormhole_data.server_ca_org_copy(actor.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    SELECT * INTO recipient FROM wormhole_data.keys k WHERE (k.key_id,k.key_version)=(org_encryption.org_key_id,org_encryption.org_key_version)
        AND k.kind='org-enc' AND k.owner_id IS NULL AND k.status='active' AND k.suite=2 AND octet_length(k.public_key)=32
        AND (k.cert_signer_key_id,k.cert_signer_key_version)=(org_signing.org_key_id,org_signing.org_key_version)
        AND k.cert_revision=1 AND octet_length(k.cert_signature)=64 FOR SHARE NOWAIT;
    IF NOT FOUND OR issuer IS DISTINCT FROM jsonb_build_object('id',org_signing.org_key_id,'version',org_signing.org_key_version)
        OR previous->'recovery' IS DISTINCT FROM jsonb_build_object('id',recipient.key_id,'version',recipient.key_version) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;
    SELECT coalesce(jsonb_agg(k.value ORDER BY b.ordinality,k.ordinality),'[]') INTO refs FROM jsonb_array_elements(scope) WITH ORDINALITY b
        CROSS JOIN LATERAL jsonb_array_elements(b.value->'keys') WITH ORDINALITY k;
    IF p_publication IS NULL THEN
        escrow:='[]';
        FOR ref IN SELECT value FROM jsonb_array_elements(refs) LOOP
            SELECT * INTO STRICT copy_row FROM wormhole_data.key_copy_record((ref->>'id')::uuid,(ref->>'version')::integer,
                recipient.key_id,recipient.key_version,meta.epoch,meta.change_seq);
            escrow:=escrow||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(copy_row)));
        END LOOP;
        status:='ready'; snapshot:=document; roster:=next_roster;
        sign_id:=org_signing.org_key_id; sign_version:=org_signing.org_key_version;
        sign_enc:=org_signing.enc; sign_ciphertext:=org_signing.ciphertext; sign_proof:=org_signing.signature;
        org_id:=recipient.key_id; org_version:=recipient.key_version; org_enc:=org_encryption.enc;
        org_ciphertext:=org_encryption.ciphertext; org_proof:=org_encryption.signature;
        org_public:=recipient.public_key; org_certificate:=recipient.cert_signature;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'member_addition_custody','key_copy_released');
        RETURN NEXT; RETURN;
    END IF;
    next_raw:=p_publication->>'manifest'; next_doc:=next_raw::jsonb;
    IF octet_length(next_raw) IS NULL OR octet_length(next_raw)>4096 OR jsonb_typeof(p_publication->'copies') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_publication->'roots') IS DISTINCT FROM 'array' OR jsonb_array_length(p_publication->'roots')<>jsonb_array_length(refs)
        OR jsonb_array_length(p_publication->'copies')<>jsonb_array_length(convert_from(next_roster,'UTF8')::jsonb)+1
        OR next_doc-ARRAY['groupRevision','rosterDigest','key','signature'] IS DISTINCT FROM previous-ARRAY['groupRevision','rosterDigest','key','signature']
        OR next_doc->'groupRevision' IS DISTINCT FROM to_jsonb(p_revision)
        OR next_doc->>'rosterDigest' IS DISTINCT FROM encode(wormhole_data.group_key_review(p_group,p_revision,next_roster),'base64')
        OR next_doc#>'{key,key}' IS DISTINCT FROM jsonb_build_object('id',old.key_id,'version',old.key_version+1)
        OR next_doc#>'{key,public}' IS NOT DISTINCT FROM previous#>'{key,public}'
        OR octet_length(decode(next_doc#>>'{key,public}','base64')) IS DISTINCT FROM 32
        OR octet_length(decode(next_doc->>'signature','base64')) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid member addition publication' USING ERRCODE='22023';
    END IF;
    UPDATE wormhole_data.keys k SET status='retired',row_version=row_version+1 WHERE (k.key_id,k.key_version)=(old.key_id,old.key_version);
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
    VALUES(old.key_id,old.key_version+1,'group',p_group,2,decode(next_doc#>>'{key,public}','base64'));
    FOR item IN SELECT value FROM jsonb_array_elements(convert_from(next_roster,'UTF8')::jsonb||jsonb_build_array(jsonb_build_array(NULL,recipient.key_id,recipient.key_version::text))) LOOP
        PERFORM wormhole_data.insert_member_addition_copy(p_publication->'copies'->position,next_doc#>'{key,key}',
            jsonb_build_object('id',(item->>1)::uuid,'version',(item->>2)::integer),issuer);
        position:=position+1;
    END LOOP;
    position:=0;
    FOR ref IN SELECT value FROM jsonb_array_elements(refs) LOOP
        PERFORM wormhole_data.insert_member_addition_copy(p_publication->'roots'->position,ref,next_doc#>'{key,key}',issuer);
        position:=position+1;
    END LOOP;
    DELETE FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(old.key_id,old.key_version)
        OR (c.holder_key_id,c.holder_key_version)=(old.key_id,old.key_version);
    INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES(p_group,subject);
    manifest:=convert_to(next_raw,'UTF8');
    UPDATE wormhole_data.groups SET key_manifest=manifest,row_version=row_version+1 WHERE id=p_group;
    INSERT INTO wormhole_data.group_member_additions VALUES(p_request,p_group,subject,p_revision,p_review,old.key_id,old.key_version+1);
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,admin_group_id,admin_subject_id)
    VALUES(actor.actor,actor.session_id,session_user,'ui','group_keyed_member_addition','success',inet_client_addr(),actor.app_version,p_group,subject);
    status:='added'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bytea,NULL::bytea,NULL::bytea,NULL::jsonb,NULL::uuid,NULL::integer,NULL::bytea,
        NULL::bytea,NULL::bytea,NULL::uuid,NULL::integer,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea,NULL::bytea;
END
$add$;

REVOKE ALL ON TABLE wormhole_data.group_member_additions FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.member_addition_scope(uuid,uuid,wormhole_data.keys,boolean,jsonb),
    wormhole_data.insert_member_addition_copy(jsonb,jsonb,jsonb,jsonb),
    wormhole_api_v1.add_keyed_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,text,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.add_keyed_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,text,bytea,jsonb)
    TO wh_{{TAG}}_user;

{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=68 WHERE singleton;
COMMIT;
