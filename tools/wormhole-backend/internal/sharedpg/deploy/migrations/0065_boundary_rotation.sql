-- Version 65: rotate shared boundary roots when reducing a group grant.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>64 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Only existing holders whose grants and certified recipients are still current
-- may receive the replacement root. This does not widen an existing grant.
CREATE FUNCTION wormhole_data.boundary_rotation_recipients(p_boundary uuid,p_group uuid,p_bit integer,p_old uuid,p_old_version integer,
    p_org uuid,p_org_version integer) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $recipients$
DECLARE held record; certificate record; members record; document jsonb; proof jsonb; result jsonb:='[]'; visited integer:=0;
BEGIN
    result:=jsonb_build_array(jsonb_build_object('kind','org','key',jsonb_build_object('id',p_org,'version',p_org_version)));
    FOR held IN
        SELECT k.* FROM wormhole_data.key_copies c JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
        WHERE (c.key_id,c.key_version)=(p_old,p_old_version) AND k.status='active' AND k.kind<>'org-enc'
        ORDER BY k.key_id,k.key_version LIMIT 1025
    LOOP
        visited:=visited+1;
        IF visited>1024 THEN RAISE EXCEPTION 'Boundary recipient set is too large' USING ERRCODE='WH020'; END IF;
        IF held.kind='user-enc' THEN
            IF NOT EXISTS(SELECT FROM wormhole_data.users u JOIN wormhole_data.boundary_grants g ON g.user_id=u.id
                WHERE u.id=held.owner_id AND NOT u.disabled AND g.boundary_id=p_boundary AND (g.permissions & p_bit)=p_bit) THEN
                CONTINUE;
            END IF;
            SELECT e.certificate,s.signed_state INTO certificate
            FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_states s USING(user_id)
            WHERE e.user_id=held.owner_id AND (e.encryption_key_id,e.encryption_key_version)=(held.key_id,held.key_version)
                AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true';
            IF NOT FOUND THEN RAISE EXCEPTION 'Current rotation recipient unavailable' USING ERRCODE='WH020'; END IF;
            proof:=jsonb_build_array(jsonb_build_array(held.owner_id,held.key_id,held.key_version::text,
                encode(certificate.signed_state,'hex'),encode(certificate.certificate,'hex')));
            document:=jsonb_build_object('kind','user','subject',held.owner_id,'proof',proof::text);
        ELSIF held.kind='group' THEN
            IF held.owner_id=p_group OR NOT EXISTS(SELECT FROM wormhole_data.boundary_grants g WHERE g.group_id=held.owner_id
                AND g.boundary_id=p_boundary AND (g.permissions & p_bit)=p_bit) THEN
                CONTINUE;
            END IF;
            SELECT convert_from(g.key_manifest,'UTF8')::jsonb AS manifest,encode(g.key_manifest,'hex') AS body INTO certificate
            FROM wormhole_data.groups g WHERE g.id=held.owner_id AND g.key_manifest IS NOT NULL;
            IF NOT FOUND THEN RAISE EXCEPTION 'Current group recipient unavailable' USING ERRCODE='WH020'; END IF;
            SELECT * INTO STRICT members FROM wormhole_data.group_key_roster(held.owner_id);
            IF members.status<>'ready' OR certificate.manifest#>'{key,key}' IS DISTINCT FROM
                jsonb_build_object('id',held.key_id,'version',held.key_version) OR
                certificate.manifest->>'rosterDigest' IS DISTINCT FROM
                encode(wormhole_data.group_key_review(held.owner_id,(certificate.manifest->>'groupRevision')::bigint,members.body),'base64') THEN
                RAISE EXCEPTION 'Current group recipient needs rotation' USING ERRCODE='WH020';
            END IF;
            document:=jsonb_build_object('kind','group','subject',held.owner_id,'manifest',certificate.body,'proof',convert_from(members.body,'UTF8'));
        ELSE
            RAISE EXCEPTION 'Unsupported boundary recipient' USING ERRCODE='WH020';
        END IF;
        result:=result||jsonb_build_array(document||jsonb_build_object('key',jsonb_build_object('id',held.key_id,'version',held.key_version)));
        IF jsonb_array_length(result)>1024 OR octet_length(result::text)>33554432 THEN
            RAISE EXCEPTION 'Boundary recipient set is too large' USING ERRCODE='WH020';
        END IF;
    END LOOP;
    RETURN result;
END
$recipients$;

CREATE FUNCTION wormhole_data.boundary_rotation_graph(p_boundary uuid,p_group uuid,p_removed integer,p_manifest jsonb,
    p_org uuid,p_org_version integer,p_epoch bigint,p_change_seq bigint) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' AS $graph$
DECLARE bit integer; purpose text; root_id uuid; root_version integer; recipient_set jsonb;
    result jsonb:='[]'; dek_rows jsonb; escrow_row record; escrow_wire jsonb; count_deks integer; budget integer;
BEGIN
    FOR bit IN 0..1 LOOP
        IF (p_removed & (1<<bit))=0 THEN CONTINUE; END IF;
        purpose:=CASE WHEN bit=0 THEN 'view' ELSE 'secret' END;
        root_id:=(p_manifest#>>ARRAY[purpose,'key','id'])::uuid;
        root_version:=(p_manifest#>>ARRAY[purpose,'key','version'])::integer;
        IF root_version>=2147483647 OR NOT EXISTS(SELECT FROM wormhole_data.keys k WHERE (k.key_id,k.key_version)=(root_id,root_version)
            AND k.kind='boundary-'||purpose AND k.owner_id=p_boundary AND k.status='active' AND k.suite=2
            AND k.public_key=decode(p_manifest#>>ARRAY[purpose,'public'],'base64')) THEN
            RAISE EXCEPTION 'Current boundary root unavailable' USING ERRCODE='WH020';
        END IF;
        IF EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.invites i
            ON (c.holder_key_id,c.holder_key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version)
            WHERE (c.key_id,c.key_version)=(root_id,root_version) AND i.used_at IS NULL AND i.expires_at>statement_timestamp()) THEN
            RAISE EXCEPTION 'A pending invitation uses the boundary root' USING ERRCODE='WH020';
        END IF;
        SELECT * INTO STRICT escrow_row FROM wormhole_data.key_copy_record(root_id,root_version,p_org,p_org_version,p_epoch,p_change_seq);
        escrow_wire:=wormhole_data.key_copy_wire(to_jsonb(escrow_row));
        recipient_set:=wormhole_data.boundary_rotation_recipients(p_boundary,p_group,1<<bit,root_id,root_version,p_org,p_org_version);
        IF EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k USING(key_id,key_version)
            WHERE (c.holder_key_id,c.holder_key_version)=(root_id,root_version) AND k.kind<>'dek') THEN
            RAISE EXCEPTION 'Unsupported boundary copy graph' USING ERRCODE='WH020';
        END IF;
        SELECT count(*) INTO count_deks FROM (SELECT FROM wormhole_data.key_copies c
            WHERE (c.holder_key_id,c.holder_key_version)=(root_id,root_version) LIMIT 8193) existing;
        IF count_deks>8192 THEN RAISE EXCEPTION 'Boundary copy graph is too large' USING ERRCODE='WH020'; END IF;
        budget:=50331648-octet_length(result::text)-octet_length(recipient_set::text)-octet_length(escrow_wire::text);
        WITH projected AS MATERIALIZED (
            SELECT c.key_id,c.key_version,wormhole_data.key_copy_wire(to_jsonb(r)) AS wire
            FROM wormhole_data.key_copies c
            CROSS JOIN LATERAL wormhole_data.key_copy_record(c.key_id,c.key_version,root_id,root_version,p_epoch,p_change_seq) r
            WHERE (c.holder_key_id,c.holder_key_version)=(root_id,root_version)
        ), bounded AS (
            SELECT p.*,sum(octet_length(p.wire::text)+2) OVER (ORDER BY p.key_id,p.key_version) AS used
            FROM projected p
        )
        SELECT coalesce(jsonb_agg(b.wire ORDER BY b.key_id,b.key_version),'[]'::jsonb) INTO dek_rows FROM bounded b WHERE b.used<=budget;
        IF jsonb_array_length(dek_rows)<>count_deks THEN
            RAISE EXCEPTION 'Boundary copy graph is too large' USING ERRCODE='WH020';
        END IF;
        result:=result||jsonb_build_array(jsonb_build_object('purpose',purpose,'recipients',recipient_set,
            'escrow',escrow_wire,'deks',dek_rows));
        IF octet_length(result::text)>50331648 THEN RAISE EXCEPTION 'Boundary copy graph is too large' USING ERRCODE='WH020'; END IF;
    END LOOP;
    RETURN result;
END
$graph$;

{{BOUNDARY_ROTATION_API}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.boundary_rotation_graph(uuid,uuid,integer,jsonb,uuid,integer,bigint,bigint),
    wormhole_data.boundary_rotation_recipients(uuid,uuid,integer,uuid,integer,uuid,integer)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=65 WHERE singleton;
COMMIT;
