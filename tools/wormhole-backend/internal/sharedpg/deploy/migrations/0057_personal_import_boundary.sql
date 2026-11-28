-- Version 57: authenticated destination selection and escrowed personal imports.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>56 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- The same UUIDv8 derivation runs in Go. It binds the selection to the owner
-- and lets a later admission reconcile a committed provisioning without a
-- local checkpoint or a new root generation.
CREATE FUNCTION wormhole_data.personal_import_boundary_id(p_workspace uuid,p_owner uuid)
RETURNS uuid LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $id$
    SELECT pg_catalog.overlay(pg_catalog.overlay(pg_catalog.substr(pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to('wormhole/v1/personal-import-boundary:'||p_workspace::text||':'||p_owner::text,'UTF8')
    ),'hex'),1,32),'8',13,1),'8',17,1)::uuid;
$id$;

CREATE FUNCTION wormhole_data.personal_import_is_escrowed(p_boundary uuid,p_owner uuid,p_recipient uuid,p_version integer,
    p_signer uuid,p_signer_version integer)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $check$
    SELECT EXISTS (
        SELECT FROM wormhole_data.boundaries b JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        CROSS JOIN LATERAL (SELECT pg_catalog.convert_from(m.body,'UTF8')::jsonb AS body) d
        WHERE b.id=p_boundary AND b.owner_user_id=p_owner AND NOT b.deleted
          AND (m.signer_key_id,m.signer_key_version)=(p_signer,p_signer_version)
          AND d.body->>'ownerUserId'=p_owner::text AND d.body->>'boundaryId'=p_boundary::text
          AND d.body->'orgEscrow'='true'::jsonb AND d.body->'active'='true'::jsonb
          AND d.body->'previousView'='null'::jsonb AND d.body->'previousSecret'='null'::jsonb
          AND 2=(SELECT count(*) FROM (VALUES ('view','boundary-view'),('secret','boundary-secret')) r(label,kind)
              JOIN wormhole_data.keys k
                ON (k.key_id,k.key_version)=((d.body#>>ARRAY[r.label,'key','id'])::uuid,
                    (d.body#>>ARRAY[r.label,'key','version'])::integer)
              JOIN wormhole_data.key_copies c USING(key_id,key_version)
              WHERE k.owner_id=b.id AND k.kind=r.kind AND k.status='active' AND k.suite=2
                AND k.public_key=pg_catalog.decode(d.body#>>ARRAY[r.label,'public'],'base64')
                AND (c.holder_key_id,c.holder_key_version)=(p_recipient,p_version)
                AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version)
                AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48));
$check$;

CREATE FUNCTION wormhole_data.personal_import_boundaries_recoverable(p_workspace uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $recoverable$
    SELECT NOT EXISTS (
        SELECT FROM wormhole_data.boundaries b
        WHERE NOT b.deleted AND b.owner_user_id IS NOT NULL
          AND (b.id<>wormhole_data.personal_import_boundary_id(p_workspace,b.owner_user_id) OR NOT EXISTS(
              SELECT FROM wormhole_data.keys e CROSS JOIN wormhole_data.keys s
              WHERE e.kind='org-enc' AND e.owner_id IS NULL AND e.status='active' AND e.suite=2
                AND s.kind='org-sign' AND s.owner_id IS NULL AND s.status='active' AND s.suite=1
                AND wormhole_data.personal_import_is_escrowed(b.id,b.owner_user_id,e.key_id,e.key_version,s.key_id,s.key_version))));
$recoverable$;

CREATE FUNCTION wormhole_data.select_import_boundary(p_workspace uuid,p_actor uuid,p_personal boolean)
RETURNS bytea LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $selection$
DECLARE item wormhole_data.boundaries; saved bytea;
BEGIN
    IF p_personal THEN
        SELECT b.* INTO item FROM wormhole_data.boundaries b
        WHERE b.id=wormhole_data.personal_import_boundary_id(p_workspace,p_actor) FOR SHARE NOWAIT;
        IF NOT FOUND THEN RETURN NULL; END IF;
        IF item.owner_user_id IS DISTINCT FROM p_actor THEN
            RAISE EXCEPTION 'Personal import destination mismatch' USING ERRCODE='WH025';
        END IF;
    ELSE
        SELECT b.* INTO STRICT item FROM wormhole_data.boundaries b WHERE NOT b.deleted AND b.owner_user_id IS NULL FOR SHARE NOWAIT;
    END IF;
    IF item.deleted OR (wormhole_data.effective_boundary_permissions(p_actor,item.id)&4)<>4 THEN
        RAISE EXCEPTION 'Import destination requires boundary Write' USING ERRCODE='42501';
    END IF;
    SELECT m.body INTO STRICT saved FROM wormhole_data.boundary_manifests m WHERE m.boundary_id=item.id FOR SHARE NOWAIT;
    RETURN saved;
END
$selection$;

CREATE FUNCTION wormhole_api_v1.workspace_import_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_personal boolean) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $lookup$
DECLARE selected record;
BEGIN
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR p_personal IS NULL THEN RAISE EXCEPTION 'Import destination unavailable' USING ERRCODE='WH025'; END IF;
    RETURN wormhole_data.select_import_boundary('{{WORKSPACE_ID}}'::uuid,selected.actor,p_personal);
END
$lookup$;

CREATE FUNCTION wormhole_api_v1.personal_import_signer(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,
    recipient_id uuid,recipient_version integer,recipient_public bytea,recipient_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $signer$
DECLARE selected record; signing record;
BEGIN
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR NOT selected.custodian OR octet_length(selected.recipient_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Personal import requires workspace custody' USING ERRCODE='WH020';
    END IF;
    SELECT * INTO STRICT signing FROM wormhole_data.server_ca_org_copy(selected.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,'personal_import_signer','key_copy_released');
    RETURN QUERY SELECT signing.org_key_id,signing.org_key_version,signing.enc,signing.ciphertext,signing.signature,
        selected.recipient_id,selected.recipient_version,selected.recipient_public,selected.recipient_signature;
END
$signer$;

CREATE FUNCTION wormhole_api_v1.provision_personal_import_boundary(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_manifest text,p_copies jsonb) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $provision$
DECLARE selected record; boundary uuid; saved bytea; body jsonb; key_data jsonb; copy jsonb; binding jsonb; bundle jsonb; label text;
        view_key uuid; secret_key uuid; root uuid; recipient uuid; version integer; i integer;
        proof bytea; wrapped bytea; encapsulated bytea;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed'
       OR COALESCE(octet_length(p_manifest),0) NOT BETWEEN 2 AND 8192
       OR pg_catalog.jsonb_typeof(p_copies) IS DISTINCT FROM 'array'
       OR octet_length(p_copies::text)>4096 THEN
        RAISE EXCEPTION 'Invalid personal import destination' USING ERRCODE='WH025';
    END IF;
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND OR NOT selected.custodian OR octet_length(selected.recipient_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Personal import requires workspace custody' USING ERRCODE='WH020';
    END IF;
    saved:=wormhole_data.select_import_boundary('{{WORKSPACE_ID}}'::uuid,selected.actor,true);
    IF saved IS NOT NULL THEN RETURN saved; END IF;

    boundary:=wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,selected.actor);
    body:=p_manifest::jsonb;
    IF body->'formatVersion' IS DISTINCT FROM '1'::jsonb OR body->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}'
       OR body->>'boundaryId' IS DISTINCT FROM boundary::text OR body->>'ownerUserId' IS DISTINCT FROM selected.actor::text
       OR body->'revision' IS DISTINCT FROM '1'::jsonb OR body->'active' IS DISTINCT FROM 'true'::jsonb
       OR body->'orgEscrow' IS DISTINCT FROM 'true'::jsonb OR body->'previousView' IS DISTINCT FROM 'null'::jsonb
       OR body->'previousSecret' IS DISTINCT FROM 'null'::jsonb
       OR body#>>'{signer,id}' IS DISTINCT FROM selected.organisation_signer::text
       OR body#>>'{signer,version}' IS DISTINCT FROM selected.organisation_version::text
       OR pg_catalog.jsonb_array_length(p_copies)<>4 THEN
        RAISE EXCEPTION 'Invalid personal import destination' USING ERRCODE='WH025';
    END IF;
    proof:=pg_catalog.decode(body->>'signature','base64');
    IF octet_length(proof) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid personal import destination signature' USING ERRCODE='WH025';
    END IF;
    INSERT INTO wormhole_data.boundaries(id,owner_user_id) VALUES(boundary,selected.actor);
    FOREACH label IN ARRAY ARRAY['view','secret'] LOOP
        key_data:=body->label;
        root:=(key_data#>>'{key,id}')::uuid;
        wrapped:=pg_catalog.decode(key_data->>'public','base64');
        IF root IS NULL OR key_data#>'{key,version}' IS DISTINCT FROM '1'::jsonb OR octet_length(wrapped) IS DISTINCT FROM 32 THEN
            RAISE EXCEPTION 'Invalid personal import destination root' USING ERRCODE='WH025';
        END IF;
        IF label='view' THEN view_key:=root; ELSE secret_key:=root; END IF;
        INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
            VALUES(root,1,'boundary-'||label,boundary,2,wrapped);
    END LOOP;
    FOR i IN 0..3 LOOP
        copy:=p_copies->i;
        binding:=copy->'binding';
        bundle:=copy->'envelope';
        root:=CASE WHEN i<2 THEN view_key ELSE secret_key END;
        recipient:=CASE WHEN i%2=0 THEN p_holder ELSE selected.recipient_id END;
        version:=CASE WHEN i%2=0 THEN p_holder_version ELSE selected.recipient_version END;
        proof:=pg_catalog.decode(copy->>'signature','base64');
        wrapped:=pg_catalog.decode(bundle->>'ciphertext','base64');
        encapsulated:=pg_catalog.decode(bundle->>'enc','base64');
        IF binding->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}'
           OR binding->'key' IS DISTINCT FROM pg_catalog.jsonb_build_object('id',root,'version',1)
           OR binding->'holder' IS DISTINCT FROM pg_catalog.jsonb_build_object('id',recipient,'version',version)
           OR binding->'issuer' IS DISTINCT FROM body->'signer'
           OR bundle->'formatVersion' IS DISTINCT FROM '1'::jsonb OR bundle->'suiteId' IS DISTINCT FROM '2'::jsonb
           OR octet_length(proof) IS DISTINCT FROM 64 OR octet_length(wrapped) IS DISTINCT FROM 48
           OR octet_length(encapsulated) IS DISTINCT FROM 32 THEN
            RAISE EXCEPTION 'Invalid personal import destination copy' USING ERRCODE='WH025';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,
            issuer_key_id,issuer_key_version,signature)
        VALUES(root,1,recipient,version,2,encapsulated,wrapped,selected.organisation_signer,selected.organisation_version,proof);
    END LOOP;
    saved:=pg_catalog.convert_to(p_manifest,'UTF8');
    INSERT INTO wormhole_data.boundary_manifests(boundary_id,body,signer_key_id,signer_key_version,signature)
        VALUES(boundary,saved,selected.organisation_signer,selected.organisation_version,pg_catalog.decode(body->>'signature','base64'));
    INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES(boundary,selected.actor,31);
    PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,'provision_personal_import_boundary','provisioned');
    RETURN saved;
EXCEPTION WHEN data_exception OR integrity_constraint_violation THEN
    RAISE EXCEPTION 'Invalid personal import destination' USING ERRCODE='WH025';
END
$provision$;

{{ADMIN_RECOVERY_MATERIAL_DEFINITION}}
{{EXPORT_WORKSPACE_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.personal_import_boundary_id(uuid,uuid),
    wormhole_data.personal_import_is_escrowed(uuid,uuid,uuid,integer,uuid,integer),
    wormhole_data.personal_import_boundaries_recoverable(uuid),
    wormhole_data.select_import_boundary(uuid,uuid,boolean)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.workspace_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean),
    wormhole_api_v1.personal_import_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.provision_personal_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,jsonb)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.workspace_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean),
    wormhole_api_v1.personal_import_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.provision_personal_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,jsonb)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=57 WHERE singleton;
COMMIT;
