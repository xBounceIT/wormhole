CREATE OR REPLACE FUNCTION wormhole_data.admin_recovery_material() RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE meta record; saved record; b record; enc record; sign record; copies jsonb; body jsonb; profile jsonb;
BEGIN
    IF session_user<>'wh_{{TAG}}_deployer' OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) THEN
        RAISE EXCEPTION 'Workspace recovery requires its TLS deployer login' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<48 OR
       meta.state<>'ready' OR NOT meta.require_tls OR meta.tls_bundle IS NULL OR meta.tls_sequence<1 OR
       meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace recovery is unavailable' USING ERRCODE='WH002';
    END IF;
    profile:=pg_catalog.convert_from(meta.signed_profile,'UTF8')::jsonb->'policy';
    IF NOT COALESCE(profile->>'profile' IN ('default','standard') AND profile->>'orgEscrow'='true',false) THEN
        RAISE EXCEPTION 'Workspace recovery profile is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT recovery_capsule INTO STRICT saved FROM wormhole_data.workspace_bootstrap WHERE singleton FOR SHARE NOWAIT;
    -- The recovered administrator receives the workspace boundary. Validate
    -- any additional authority requirements before issuing the invitation.
    SELECT m.boundary_id,m.version,m.body INTO STRICT b
    FROM wormhole_data.boundaries r JOIN wormhole_data.boundary_manifests m ON m.boundary_id=r.id
    WHERE NOT r.deleted AND r.owner_user_id IS NULL FOR SHARE OF r,m NOWAIT;
{{LEGACY_BOUNDARY_GUARD}}    SELECT key_id,key_version,public_key INTO STRICT enc FROM wormhole_data.keys
    WHERE kind='org-enc' AND owner_id IS NULL AND status='active' AND suite=2 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    SELECT key_id,key_version,public_key INTO STRICT sign FROM wormhole_data.keys
    WHERE kind='org-sign' AND owner_id IS NULL AND status='active' AND suite=1 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
{{ADDITIONAL_BOUNDARY_GUARD}}    body:=pg_catalog.convert_from(b.body,'UTF8')::jsonb;
    IF NOT COALESCE(body->>'active'='true' AND body->>'orgEscrow'='true' AND
        body->'previousView'='null'::jsonb AND body->'previousSecret'='null'::jsonb,false) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
    SELECT pg_catalog.jsonb_agg(item.copy ORDER BY item.kind) INTO copies
    FROM (
        SELECT k.kind,pg_catalog.jsonb_build_object(
            'id',k.key_id,'version',k.key_version,'kind',k.kind,
            'enc',pg_catalog.encode(c.enc,'base64'),'ciphertext',pg_catalog.encode(c.ciphertext,'base64'),
            'signature',pg_catalog.encode(c.signature,'base64')) AS copy
        FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING (key_id,key_version)
        WHERE k.owner_id=b.boundary_id AND k.status='active' AND
            ((k.kind='boundary-secret' AND (k.key_id,k.key_version)=
                ((body#>>'{secret,key,id}')::uuid,(body#>>'{secret,key,version}')::integer))
             OR (k.kind='boundary-view' AND (k.key_id,k.key_version)=
                ((body#>>'{view,key,id}')::uuid,(body#>>'{view,key,version}')::integer)))
            AND (c.holder_key_id,c.holder_key_version)=(enc.key_id,enc.key_version)
            AND (c.issuer_key_id,c.issuer_key_version)=(sign.key_id,sign.key_version)
            AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
        FOR SHARE OF k,c NOWAIT
    ) item;
    IF COALESCE(pg_catalog.jsonb_array_length(copies),0)<>2 THEN
        RAISE EXCEPTION 'Workspace recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'workspaceId',meta.workspace_id,'roleTag',meta.role_tag,'database',pg_catalog.current_database(),
        'tlsDigest',pg_catalog.encode(pg_catalog.sha256(meta.tls_bundle),'hex'),
        'policy',pg_catalog.encode(meta.signed_profile,'base64'),
        'capsule',pg_catalog.encode(saved.recovery_capsule,'base64'),
        'organisationEncryption',pg_catalog.jsonb_build_object('id',enc.key_id,'version',enc.key_version),
        'organisationSigning',pg_catalog.jsonb_build_object('id',sign.key_id,'version',sign.key_version),
        'organisation',pg_catalog.jsonb_build_object('encryption',pg_catalog.encode(enc.public_key,'base64'),
            'signing',pg_catalog.encode(sign.public_key,'base64')),
        'boundaryId',b.boundary_id,'boundary',pg_catalog.encode(b.body,'base64'),'boundaryVersion',b.version,
        'copies',copies);
END
$material$;
