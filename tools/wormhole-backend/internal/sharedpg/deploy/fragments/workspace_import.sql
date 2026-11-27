CREATE{{IMPORT_REPLACE}} FUNCTION wormhole_api_v1.commit_workspace_import(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_document text,p_signature bytea) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='25s' AS $import$
DECLARE actor record; written wormhole_data.workspace_import_receipts; target uuid; request uuid; digest bytea;
        raw_doc json; doc jsonb; entry jsonb; metadata jsonb; manifest jsonb; seal bytea; root record;
        imported bytea; extra jsonb; pin jsonb; raw_value json; binding jsonb; envelope jsonb;
        wrapped jsonb; payload jsonb; enc bytea; cipher bytea;
        node_row wormhole_data.nodes; credential_row wormhole_data.credential_profiles;
        tunnel_row wormhole_data.tunnel_profiles; value_row wormhole_data.secret_values;
        boundary uuid; scope_owner uuid; object_owner uuid; object_boundary uuid; object_kind smallint;
        permitted integer; scope_permissions jsonb:='{}'::jsonb; holders jsonb:='{}'::jsonb;
        roots uuid[]:='{}'::uuid[]; nodes uuid[]:='{}'::uuid[]; credentials uuid[]:='{}'::uuid[]; tunnels uuid[]:='{}'::uuid[];
        dependency uuid; expected_values integer:=0;{{NOTE_DECLARATIONS}}
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' OR
       COALESCE(octet_length(p_document),0) NOT BETWEEN 2 AND 134217728 OR octet_length(p_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid workspace import' USING ERRCODE='WH025';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace import is unavailable' USING ERRCODE='42501'; END IF;
    SELECT workspace_id INTO STRICT target FROM wormhole_data.workspace_meta WHERE singleton;
    raw_doc:=p_document::json;
    doc:=raw_doc::jsonb;
    request:=(doc#>>'{target,requestId}')::uuid;
    IF pg_catalog.jsonb_typeof(doc) IS DISTINCT FROM 'object' OR doc->'formatVersion' IS DISTINCT FROM '1'::jsonb
       OR (doc#>>'{target,workspaceId}') IS DISTINCT FROM target::text OR doc#>>'{target,userId}' IS DISTINCT FROM actor.actor::text
       OR request IS NULL OR request='00000000-0000-0000-0000-000000000000'::uuid
       OR doc#>>'{author,id}' IS DISTINCT FROM p_signer::text OR doc#>'{author,version}' IS DISTINCT FROM pg_catalog.to_jsonb(p_signer_version)
       OR octet_length(pg_catalog.decode(doc->>'sourceDigest','base64')) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid workspace import identity' USING ERRCODE='WH025';
    END IF;
    digest:=pg_catalog.sha256(pg_catalog.convert_to(p_document,'UTF8') || p_signature);
    SELECT * INTO written FROM wormhole_data.workspace_import_receipts r WHERE r.request_id=request;
    IF FOUND THEN
        IF written.actor_id=actor.actor AND written.digest=digest THEN RETURN 'already-imported'; END IF;
        RAISE EXCEPTION 'Workspace import request already allocated' USING ERRCODE='WH025';
    END IF;
    IF EXISTS(SELECT FROM pg_catalog.unnest(ARRAY['boundaries','nodes','credentials','tunnels','values']) k
        WHERE pg_catalog.jsonb_typeof(doc->k) IS DISTINCT FROM 'array') THEN
        RAISE EXCEPTION 'Invalid workspace import graph' USING ERRCODE='WH025';
    END IF;
    IF pg_catalog.jsonb_array_length(doc->'boundaries') NOT BETWEEN 1 AND 2 OR
       pg_catalog.jsonb_array_length(doc->'nodes')+pg_catalog.jsonb_array_length(doc->'credentials')+
       pg_catalog.jsonb_array_length(doc->'tunnels')+pg_catalog.jsonb_array_length(doc->'values') NOT BETWEEN 1 AND 50000 THEN
        RAISE EXCEPTION 'Workspace import graph outside limits' USING ERRCODE='WH025';
    END IF;

    -- Match the exact manifest revisions approved for sealing. Only an owner
    -- or a member already holding boundary Write may populate that boundary.
    FOR entry IN SELECT value FROM pg_catalog.jsonb_array_elements(doc->'boundaries') LOOP
        boundary:=(entry->>'id')::uuid;
        SELECT b.owner_user_id,m.body INTO root FROM wormhole_data.boundaries b JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
        WHERE b.id=boundary AND NOT b.deleted AND m.version=(entry->>'revision')::bigint
          AND pg_catalog.sha256(m.body)=pg_catalog.decode(entry->>'digest','base64') FOR SHARE OF b,m NOWAIT;
        IF NOT FOUND OR (root.owner_user_id IS NOT NULL AND root.owner_user_id<>actor.actor) OR boundary=ANY(roots) THEN
            RAISE EXCEPTION 'Workspace import boundary changed' USING ERRCODE='WH025';
        END IF;
        manifest:=pg_catalog.convert_from(root.body,'UTF8')::jsonb;
        IF manifest->>'active' IS DISTINCT FROM 'true' OR manifest->>'orgEscrow' IS DISTINCT FROM 'true' THEN
            RAISE EXCEPTION 'Workspace import boundary is inactive' USING ERRCODE='WH025';
        END IF;
        permitted:=wormhole_data.effective_boundary_permissions(actor.actor,boundary);
        IF (permitted&4)<>4 THEN RAISE EXCEPTION 'Boundary Write is required' USING ERRCODE='42501'; END IF;
        PERFORM FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING(key_id,key_version)
        WHERE (k.key_id,k.key_version)=((manifest#>>'{secret,key,id}')::uuid,(manifest#>>'{secret,key,version}')::integer)
          AND k.owner_id=boundary AND k.kind='boundary-secret' AND k.status='active' AND k.suite=2
          AND k.public_key=pg_catalog.decode(manifest#>>'{secret,public}','base64')
          AND (c.holder_key_id,c.holder_key_version)=(p_holder,p_holder_version) AND c.suite=2;
        IF NOT FOUND THEN RAISE EXCEPTION 'Workspace import secret root is unavailable' USING ERRCODE='42501'; END IF;
        roots:=pg_catalog.array_append(roots,boundary);
        scope_permissions:=scope_permissions||pg_catalog.jsonb_build_object(boundary::text,permitted);
        holders:=holders||pg_catalog.jsonb_build_object(boundary::text,manifest#>'{secret,key}');
{{NOTE_BOUNDARY}}
    END LOOP;

    FOR entry IN SELECT value FROM pg_catalog.jsonb_array_elements(doc->'credentials') LOOP
        boundary:=(entry->>'boundaryId')::uuid;
        IF NOT COALESCE(boundary=ANY(roots),false) OR entry#>'{record,deleted}' IS DISTINCT FROM 'false'::jsonb THEN
            RAISE EXCEPTION 'Invalid imported credential boundary' USING ERRCODE='WH025';
        END IF;
        metadata:=entry#>'{record,metadata}';
        manifest:=entry#>'{record,fields}';
        SELECT * INTO credential_row FROM pg_catalog.jsonb_populate_record(NULL::wormhole_data.credential_profiles,
            wormhole_data.import_columns(metadata-'ownerUserId') || pg_catalog.jsonb_build_object('owner_user_id',NULLIF(metadata->>'ownerUserId','')));
        SELECT owner_user_id INTO scope_owner FROM wormhole_data.boundaries WHERE id=boundary;
        IF credential_row.owner_user_id IS DISTINCT FROM scope_owner OR
           NOT wormhole_data.credential_fields_valid(manifest,credential_row.kind,credential_row.provider,false) OR EXISTS(
               SELECT FROM pg_catalog.jsonb_array_elements(manifest) f WHERE f->'present'<>'true'::jsonb OR f->'version'<>'1'::jsonb) THEN
            RAISE EXCEPTION 'Invalid imported credential manifest' USING ERRCODE='WH025';
        END IF;
        credential_row.fields:=manifest;
        credential_row.boundary_id:=boundary;
        credential_row.row_version:=1; credential_row.deleted:=false; credential_row.seal_suite:=2;
        credential_row.seal_signer_key_id:=p_signer; credential_row.seal_signer_key_version:=p_signer_version;
        credential_row.seal_capability_id:=NULL; credential_row.seal:=wormhole_data.import_seal(entry->'seal',p_signer,p_signer_version);
        INSERT INTO wormhole_data.credential_profiles SELECT (credential_row).*;
        credentials:=pg_catalog.array_append(credentials,credential_row.id);
        expected_values:=expected_values+pg_catalog.jsonb_array_length(manifest);
    END LOOP;

    FOR entry IN SELECT value FROM pg_catalog.jsonb_array_elements(doc->'tunnels') LOOP
        boundary:=(entry->>'boundaryId')::uuid;
        metadata:=entry#>'{record,metadata}';
        IF NOT COALESCE(boundary=ANY(roots),false) OR entry#>'{record,deleted}' IS DISTINCT FROM 'false'::jsonb
           OR entry#>'{record,configurationVersion}' IS DISTINCT FROM '1'::jsonb THEN
            RAISE EXCEPTION 'Invalid imported tunnel boundary' USING ERRCODE='WH025';
        END IF;
        dependency:=(metadata->>'id')::uuid;
        INSERT INTO wormhole_data.tunnel_profiles(id,name,kind,configuration_version,deleted,boundary_id,row_version,
            seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
        VALUES(dependency,metadata->>'name',(metadata->>'kind')::smallint,1,false,boundary,1,2,p_signer,p_signer_version,
            wormhole_data.import_seal(entry->'seal',p_signer,p_signer_version));
        tunnels:=pg_catalog.array_append(tunnels,dependency);
        expected_values:=expected_values+1;
    END LOOP;

    FOR entry IN SELECT value FROM pg_catalog.jsonb_array_elements(doc->'nodes') LOOP
        boundary:=(entry->>'boundaryId')::uuid;
        IF NOT COALESCE(boundary=ANY(roots),false) THEN RAISE EXCEPTION 'Invalid imported node boundary' USING ERRCODE='WH025'; END IF;
        metadata:=entry->'metadata';
        SELECT * INTO node_row FROM pg_catalog.jsonb_populate_record(NULL::wormhole_data.nodes,wormhole_data.import_columns(metadata));
        SELECT owner_user_id INTO scope_owner FROM wormhole_data.boundaries WHERE id=boundary;
        IF node_row.owner_user_id IS DISTINCT FROM scope_owner OR wormhole_data.node_metadata(node_row) IS DISTINCT FROM metadata
           OR NOT wormhole_data.resolver_node_valid(metadata)
           OR node_row.credential_slot_id IS NOT NULL THEN
            RAISE EXCEPTION 'Invalid imported node metadata' USING ERRCODE='WH025';
        END IF;
        IF node_row.parent_id IS NOT NULL THEN
            SELECT kind,owner_user_id INTO object_kind,object_owner FROM wormhole_data.nodes WHERE id=node_row.parent_id AND id=ANY(nodes);
            IF NOT FOUND OR object_kind<>0 OR (scope_owner IS NULL AND object_owner IS NOT NULL) THEN
                RAISE EXCEPTION 'Invalid imported parent' USING ERRCODE='WH025';
            END IF;
        END IF;
        FOREACH dependency IN ARRAY ARRAY[node_row.credential_id,node_row.rdp_gateway_credential_id] LOOP
            IF dependency IS NULL THEN CONTINUE; END IF;
            SELECT owner_user_id INTO object_owner FROM wormhole_data.credential_profiles WHERE id=dependency AND id=ANY(credentials);
            IF NOT FOUND OR (scope_owner IS NULL AND object_owner IS NOT NULL) THEN
                RAISE EXCEPTION 'Invalid imported account dependency' USING ERRCODE='WH025';
            END IF;
        END LOOP;
        IF node_row.tunnel_config_id IS NOT NULL THEN
            SELECT b.owner_user_id INTO object_owner FROM wormhole_data.tunnel_profiles t JOIN wormhole_data.boundaries b ON b.id=t.boundary_id
            WHERE t.id=node_row.tunnel_config_id AND t.id=ANY(tunnels);
            IF NOT FOUND OR (scope_owner IS NULL AND object_owner IS NOT NULL) THEN
                RAISE EXCEPTION 'Invalid imported route dependency' USING ERRCODE='WH025';
            END IF;
        END IF;
        imported:=pg_catalog.decode(entry->>'imported','base64');
        IF (imported IS NULL) IS DISTINCT FROM (node_row.imported IS NULL) OR
           node_row.imported->>'digest' IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(imported),'hex') THEN
            RAISE EXCEPTION 'Invalid imported node data digest' USING ERRCODE='WH025';
        END IF;
        IF imported IS NOT NULL THEN
            IF octet_length(imported)>32768 THEN RAISE EXCEPTION 'Imported node data exceeds limits' USING ERRCODE='WH025'; END IF;
            extra:=pg_catalog.convert_from(imported,'UTF8')::jsonb;
            IF {{NOTE_FORMAT_INVALID}} OR extra->>'nodeId' IS DISTINCT FROM node_row.id::text
               OR NOT COALESCE(extra->>'noteVersion' IN ('0','1'),false) OR pg_catalog.jsonb_typeof(extra->'pins') IS DISTINCT FROM 'array'{{NOTE_REFERENCE_CHECK}} THEN
                RAISE EXCEPTION 'Invalid imported node data' USING ERRCODE='WH025';
            END IF;
            IF pg_catalog.jsonb_array_length(extra->'pins')>3 OR
               node_row.imported->'retainedPins' IS DISTINCT FROM pg_catalog.to_jsonb(pg_catalog.jsonb_array_length(extra->'pins')>0) THEN
                RAISE EXCEPTION 'Invalid imported pins' USING ERRCODE='WH025';
            END IF;
            FOR pin IN SELECT value FROM pg_catalog.jsonb_array_elements(extra->'pins') LOOP
                IF pin->>'nodeId' IS DISTINCT FROM node_row.id::text OR pin->'resolverVersion' IS DISTINCT FROM '0'::jsonb THEN
                    RAISE EXCEPTION 'Invalid imported pin identity' USING ERRCODE='WH025';
                END IF;
                IF pin->>'sourceKind'='saved' THEN
                    SELECT owner_user_id INTO object_owner FROM wormhole_data.credential_profiles
                    WHERE id=(pin->>'credentialId')::uuid AND id=ANY(credentials);
                    IF NOT FOUND OR (scope_owner IS NULL AND object_owner IS NOT NULL) THEN
                        RAISE EXCEPTION 'Invalid imported pin dependency' USING ERRCODE='WH025';
                    END IF;
                END IF;
            END LOOP;
            expected_values:=expected_values+(extra->>'noteVersion')::integer;
        END IF;
        node_row.row_version:=1; node_row.boundary_id:=boundary; node_row.seal_suite:=2;
        node_row.seal_signer_key_id:=p_signer; node_row.seal_signer_key_version:=p_signer_version;
        node_row.seal_capability_id:=NULL; node_row.seal:=wormhole_data.import_seal(entry->'seal',p_signer,p_signer_version);
        node_row.encrypted_metadata:=NULL; node_row.metadata_key_id:=NULL; node_row.metadata_key_version:=NULL; node_row.name_blind_index:=NULL;
        INSERT INTO wormhole_data.nodes SELECT (node_row).*;
        IF imported IS NOT NULL THEN INSERT INTO wormhole_data.node_import_data(node_id,body) VALUES(node_row.id,imported); END IF;
        manifest:=entry#>'{fields,fields}';
        IF entry#>>'{fields,nodeId}' IS DISTINCT FROM node_row.id::text OR entry#>'{fields,deleted}' IS DISTINCT FROM 'false'::jsonb
           OR NOT wormhole_data.node_fields_valid(manifest,false) OR EXISTS(
               SELECT FROM pg_catalog.jsonb_array_elements(manifest) f WHERE f->'present'<>'true'::jsonb OR f->'version'<>'1'::jsonb) THEN
            RAISE EXCEPTION 'Invalid imported node fields' USING ERRCODE='WH025';
        END IF;
        INSERT INTO wormhole_data.node_secret_manifests(node_id,fields,deleted,boundary_id,row_version,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
        VALUES(node_row.id,manifest,false,boundary,1,2,p_signer,p_signer_version,wormhole_data.import_seal(entry->'fieldsSeal',p_signer,p_signer_version));
        INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES(node_row.id,actor.actor,(scope_permissions->>boundary::text)::integer);
        nodes:=pg_catalog.array_append(nodes,node_row.id);
        expected_values:=expected_values+pg_catalog.jsonb_array_length(manifest);
    END LOOP;

    IF expected_values<>pg_catalog.jsonb_array_length(doc->'values') THEN RAISE EXCEPTION 'Incomplete imported fields' USING ERRCODE='WH025'; END IF;
    -- Use json rather than jsonb here to preserve the canonical envelope bytes
    -- accepted by the native authenticated release codec.
    FOR raw_value IN SELECT value FROM pg_catalog.json_array_elements(raw_doc->'values') LOOP
        entry:=raw_value::jsonb;
        boundary:=(entry->>'boundaryId')::uuid;
        binding:=entry->'binding';
        envelope:=entry->'envelope';
        wrapped:=entry->'keyCopy';
        payload:=wrapped->'envelope';
        value_row.owner_id:=(binding->>'OwnerID')::uuid;
        value_row.owner_kind:=binding->>'OwnerKind';
        value_row.field:=binding->>'Field';
        value_row.dek_id:=(binding#>>'{DEK,id}')::uuid;
        value_row.dek_version:=1;
        value_row.row_version:=1;
        IF NOT COALESCE(boundary=ANY(roots),false) OR binding->>'WorkspaceID' IS DISTINCT FROM target::text
           OR binding->'Version' IS DISTINCT FROM '1'::jsonb OR binding#>'{DEK,version}' IS DISTINCT FROM '1'::jsonb
           OR envelope->'formatVersion' IS DISTINCT FROM '1'::jsonb OR envelope->'suiteId' IS DISTINCT FROM '1'::jsonb
           OR envelope->>'keyId' IS DISTINCT FROM value_row.dek_id::text OR envelope->'keyVersion' IS DISTINCT FROM '1'::jsonb
           OR octet_length(pg_catalog.decode(envelope->>'nonce','base64')) IS DISTINCT FROM 12
           OR NOT COALESCE(octet_length(pg_catalog.decode(envelope->>'ciphertext','base64')) BETWEEN 16 AND 4194320,false)
           OR payload->'formatVersion' IS DISTINCT FROM '1'::jsonb OR payload->'suiteId' IS DISTINCT FROM '2'::jsonb THEN
            RAISE EXCEPTION 'Invalid imported field envelope' USING ERRCODE='WH025';
        END IF;
        object_boundary:=NULL;{{NOTE_RESET}}
        CASE value_row.owner_kind
        WHEN 'credential' THEN
            SELECT c.boundary_id INTO object_boundary FROM wormhole_data.credential_profiles c WHERE c.id=value_row.owner_id AND c.id=ANY(credentials)
              AND EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(c.fields) f WHERE f->>'field'=value_row.field);
        WHEN 'node' THEN
            SELECT n.boundary_id{{NOTE_FORMAT_SELECT}} INTO object_boundary{{NOTE_FORMAT_INTO}} FROM wormhole_data.node_secret_manifests n
            LEFT JOIN wormhole_data.node_import_data i ON i.node_id=n.node_id WHERE n.node_id=value_row.owner_id AND n.node_id=ANY(nodes)
              AND ((value_row.field='notes' AND (pg_catalog.convert_from(i.body,'UTF8')::jsonb)->>'noteVersion'='1') OR
                EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(n.fields) f WHERE f->>'field'=value_row.field));
        WHEN 'tunnel' THEN
            SELECT t.boundary_id INTO object_boundary FROM wormhole_data.tunnel_profiles t WHERE t.id=value_row.owner_id AND t.id=ANY(tunnels)
              AND value_row.field='settings';
        ELSE RAISE EXCEPTION 'Invalid imported field owner' USING ERRCODE='WH025';
        END CASE;
        IF object_boundary IS DISTINCT FROM boundary THEN RAISE EXCEPTION 'Imported field scope mismatch' USING ERRCODE='WH025'; END IF;
{{NOTE_USE_VIEW_HOLDER}}        enc:=pg_catalog.decode(payload->>'enc','base64');
        cipher:=pg_catalog.decode(payload->>'ciphertext','base64');
        seal:=pg_catalog.decode(wrapped->>'signature','base64');
        IF octet_length(enc) IS DISTINCT FROM 32 OR octet_length(cipher) IS DISTINCT FROM 48 OR octet_length(seal) IS DISTINCT FROM 64 THEN
            RAISE EXCEPTION 'Invalid imported key copy' USING ERRCODE='WH025';
        END IF;
        INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite) VALUES(value_row.dek_id,1,'dek',value_row.dek_id,1);
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
        VALUES(value_row.dek_id,1,({{VALUE_HOLDER}}->>'id')::uuid,({{VALUE_HOLDER}}->>'version')::integer,2,enc,cipher,p_signer,p_signer_version,seal);
        value_row.envelope:=pg_catalog.convert_to((raw_value->'envelope')::text,'UTF8');
        INSERT INTO wormhole_data.secret_values SELECT (value_row).*;
    END LOOP;
    INSERT INTO wormhole_data.workspace_import_receipts(request_id,actor_id,digest,signature) VALUES(request,actor.actor,digest,p_signature);
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'commit_workspace_import','imported');
    RETURN 'imported';
EXCEPTION WHEN data_exception OR integrity_constraint_violation THEN
    RAISE EXCEPTION 'Invalid or conflicting workspace import records' USING ERRCODE='WH025';
END
$import$;
