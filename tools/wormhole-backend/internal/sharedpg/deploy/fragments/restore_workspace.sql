CREATE OR REPLACE FUNCTION wormhole_api_v1.restore_workspace(p_archive text,p_database text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='90s'
SET bytea_output='hex' SET timezone='UTC'
AS $restore$
DECLARE target wormhole_data.workspace_meta; original wormhole_data.workspace_meta;
        archive jsonb; grouped jsonb; relation text;
        digest bytea; present boolean; sequence bigint;
        relations constant text[] := ARRAY[
            'users','keys','key_copies','groups','group_members','boundaries','boundary_manifests','boundary_grants',
            'user_key_states','user_key_wraps','user_enrollments','nodes','grants','credential_profiles',
            'credential_slots','credential_slot_values','user_node_overrides','tunnel_profiles',
            'node_secret_manifests','secret_values','workspace_server_ca'{{IMPORT_ARCHIVE_RELATION}}
        ];
BEGIN
    IF session_user<>'wh_{{TAG}}_deployer' OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) OR
       pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Workspace restore requires its TLS deployer login' USING ERRCODE='42501';
    END IF;
    IF p_database IS DISTINCT FROM pg_catalog.current_database() OR
       p_archive IS NULL OR pg_catalog.octet_length(p_archive) NOT BETWEEN 2 AND 47240320 THEN
        RAISE EXCEPTION 'Workspace restore rejected' USING ERRCODE='WH002';
    END IF;
    SELECT * INTO STRICT target FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF target.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR target.role_tag<>'{{TAG}}' OR
       target.schema_version<50 OR NOT target.require_tls THEN
        RAISE EXCEPTION 'Workspace restore rejected' USING ERRCODE='WH002';
    END IF;
    digest:=pg_catalog.sha256(pg_catalog.convert_to(p_archive,'UTF8'));
    IF target.state='ready' AND EXISTS(SELECT FROM wormhole_data.workspace_restore w WHERE w.singleton AND w.archive_digest=digest) THEN
        RETURN 'already-restored';
    END IF;
    IF target.state<>'provisioning' OR target.signed_profile IS NOT NULL OR target.tls_bundle IS NOT NULL THEN
        RAISE EXCEPTION 'Workspace restore requires an untouched deployment' USING ERRCODE='WH002';
    END IF;
    FOREACH relation IN ARRAY relations || ARRAY['workspace_bootstrap','workspace_restore','devices','account_auth',
        'sessions','invites','invitation_logins','device_admissions','device_confirmations','catalog_changes'] LOOP
        EXECUTE pg_catalog.format('SELECT EXISTS(SELECT FROM wormhole_data.%I)',relation) INTO present;
        IF present THEN
            RAISE EXCEPTION 'Workspace restore requires an untouched deployment' USING ERRCODE='WH002';
        END IF;
    END LOOP;

    archive:=p_archive::jsonb;
    IF pg_catalog.jsonb_typeof(archive) IS DISTINCT FROM 'object' OR
       archive->'formatVersion' IS DISTINCT FROM '1'::jsonb OR
       archive->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}' OR
       pg_catalog.jsonb_typeof(archive->'records') IS DISTINCT FROM 'array' OR
       (archive-'formatVersion'-'workspaceId'-'records')<>'{}'::jsonb THEN
        RAISE EXCEPTION 'Unsupported workspace archive' USING ERRCODE='WH002';
    END IF;
    IF pg_catalog.jsonb_array_length(archive->'records') NOT BETWEEN 2 AND 100000 THEN
        RAISE EXCEPTION 'Workspace archive exceeds limits' USING ERRCODE='WH022';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.jsonb_array_elements(archive->'records') AS item(row)
        WHERE pg_catalog.jsonb_typeof(item.row) IS DISTINCT FROM 'object'
           OR NOT COALESCE((item.row->>'relation')=ANY(relations || ARRAY['workspace_meta','workspace_bootstrap']),false)
           OR pg_catalog.jsonb_typeof(item.row->'body') IS DISTINCT FROM 'object'
           OR (item.row-'relation'-'body')<>'{}'::jsonb) THEN
        RAISE EXCEPTION 'Workspace archive contains unsupported records' USING ERRCODE='WH002';
    END IF;
    SELECT pg_catalog.jsonb_object_agg(rows.name,rows.bodies) INTO grouped
    FROM (
        SELECT item.row->>'relation' AS name,pg_catalog.jsonb_agg(item.row->'body') AS bodies
        FROM pg_catalog.jsonb_array_elements(archive->'records') AS item(row)
        GROUP BY item.row->>'relation'
    ) rows;
    IF COALESCE(pg_catalog.jsonb_array_length(grouped->'workspace_meta'),0)<>1 OR
       COALESCE(pg_catalog.jsonb_array_length(grouped->'workspace_bootstrap'),0)<>1 OR
       COALESCE(pg_catalog.jsonb_array_length(grouped->'workspace_server_ca'),0)>1 OR NOT
       (grouped ?& ARRAY['users','keys','key_copies','boundaries','boundary_manifests',
                         'user_key_states','user_key_wraps','user_enrollments']) THEN
        RAISE EXCEPTION 'Workspace archive is incomplete' USING ERRCODE='WH002';
    END IF;
    SELECT * INTO STRICT original FROM pg_catalog.jsonb_populate_record(NULL::wormhole_data.workspace_meta,grouped->'workspace_meta'->0);
    IF original.singleton IS DISTINCT FROM true OR original.workspace_id IS DISTINCT FROM target.workspace_id OR
       original.role_tag IS DISTINCT FROM target.role_tag OR NOT COALESCE(original.schema_version BETWEEN 49 AND least(target.schema_version,{{MAX_RECOVERY_SCHEMA}}),false) OR
       original.state IS DISTINCT FROM 'ready' OR original.require_tls IS DISTINCT FROM true OR
       original.min_api IS DISTINCT FROM 1 OR NOT COALESCE(original.max_api>=1,false) OR
       original.resolver_version IS DISTINCT FROM 1 OR NOT COALESCE(original.tls_sequence>=1,false) OR
       original.tls_bundle IS NULL OR original.signed_profile IS NULL OR
       NOT COALESCE(original.epoch BETWEEN 1 AND 9223372036854775806 AND
                     original.change_seq BETWEEN 0 AND 9223372036854775806,false) THEN
        RAISE EXCEPTION 'Workspace archive identity mismatch' USING ERRCODE='WH002';
    END IF;
    IF NOT COALESCE(pg_catalog.convert_from(original.signed_profile,'UTF8')::jsonb#>>'{policy,profile}' IN ('default','standard')
                AND pg_catalog.convert_from(original.signed_profile,'UTF8')::jsonb#>>'{policy,orgEscrow}'='true',false) THEN
        RAISE EXCEPTION 'Workspace restore profile is unsupported' USING ERRCODE='WH020';
    END IF;

    -- Only these persistent relations are accepted. Their order honors foreign
    -- keys, and a single insert per relation handles references within a table.
    FOREACH relation IN ARRAY relations LOOP
        IF grouped ? relation THEN
            EXECUTE pg_catalog.format('INSERT INTO wormhole_data.%1$I SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::wormhole_data.%1$I,$1)',relation)
                USING grouped->relation;
        END IF;
    END LOOP;
{{IMPORT_RESTORE_GUARD}}    INSERT INTO wormhole_data.workspace_bootstrap(singleton,invite_id,request_digest,recovery_capsule)
    SELECT true,NULL,bootstrap.request_digest,bootstrap.recovery_capsule
    FROM pg_catalog.jsonb_populate_record(NULL::wormhole_data.workspace_bootstrap,grouped->'workspace_bootstrap'->0) bootstrap
    WHERE bootstrap.singleton;
    IF NOT FOUND OR EXISTS(
        SELECT FROM wormhole_data.boundaries b
        LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        WHERE pg_catalog.convert_from(m.body,'UTF8')::jsonb->>'orgEscrow' IS DISTINCT FROM 'true'
    ) THEN
        RAISE EXCEPTION 'Workspace recovery graph is incomplete' USING ERRCODE='WH020';
    END IF;
    SELECT greatest(m.change_seq,original.change_seq)+1 INTO STRICT sequence FROM wormhole_data.workspace_meta m WHERE m.singleton;
    DELETE FROM wormhole_data.catalog_changes;
    UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile=original.signed_profile,
        tls_sequence=original.tls_sequence,tls_bundle=original.tls_bundle,min_api=original.min_api,max_api=original.max_api,
        epoch=original.epoch+1,change_seq=sequence,catalog_reset_seq=sequence WHERE singleton;
    INSERT INTO wormhole_data.workspace_restore(archive_digest) VALUES(digest);
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES('00000000-0000-0000-0000-000000000000',pg_catalog.gen_random_uuid(),session_user,'ui',
           'restore_workspace','restored',pg_catalog.inet_client_addr(),'restore-v1');
    RETURN 'restored';
END
$restore$;
