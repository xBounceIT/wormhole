CREATE FUNCTION wormhole_api_v1.export_workspace(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea)
RETURNS TABLE(relation text,body text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='25s'
SET bytea_output='hex' SET timezone='UTC'
AS $export$
DECLARE identity record; custody record; item record; records integer:=0; total bigint:=0;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    IF NOT EXISTS (SELECT FROM wormhole_data.workspace_meta
        WHERE singleton AND pg_catalog.convert_from(signed_profile,'UTF8')::jsonb#>>'{policy,orgEscrow}'='true')
        OR EXISTS (
            SELECT FROM wormhole_data.boundaries b
            LEFT JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
            WHERE pg_catalog.convert_from(m.body,'UTF8')::jsonb->>'orgEscrow' IS DISTINCT FROM 'true'
        ) THEN
        RAISE EXCEPTION 'Workspace recovery requires escrowed boundaries' USING ERRCODE='WH020';
    END IF;
{{PERSONAL_IMPORT_EXPORT_GUARD}}    -- Both current copies must be available to this certified holder.
    PERFORM * FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    SELECT * INTO STRICT custody FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    relation:='custody';
    body:=pg_catalog.jsonb_build_object('id',custody.org_key_id,'version',custody.org_key_version,
        'enc',pg_catalog.encode(custody.enc,'base64'),'ciphertext',pg_catalog.encode(custody.ciphertext,'base64'),
        'signature',pg_catalog.encode(custody.signature,'base64'))::text;
    RETURN NEXT;

    -- The complete graph is copied by one SELECT using one MVCC snapshot.
    -- Live login material, temporary capabilities and operational history
    -- belong to the source deployment. Restoration starts without them.
    FOR item IN
        SELECT 'workspace_meta'::text AS relation,pg_catalog.to_jsonb(m) AS body FROM wormhole_data.workspace_meta m
        UNION ALL
        SELECT 'users'::text,pg_catalog.to_jsonb(u) FROM wormhole_data.users u
        UNION ALL
        SELECT 'groups'::text,pg_catalog.to_jsonb(g) FROM wormhole_data.groups g
        UNION ALL
        SELECT 'group_members'::text,pg_catalog.to_jsonb(gm) FROM wormhole_data.group_members gm
        UNION ALL
        SELECT 'boundaries'::text,pg_catalog.to_jsonb(b) FROM wormhole_data.boundaries b
        UNION ALL
        SELECT 'boundary_manifests'::text,pg_catalog.to_jsonb(bm) FROM wormhole_data.boundary_manifests bm
        UNION ALL
        SELECT 'boundary_grants'::text,pg_catalog.to_jsonb(bg) FROM wormhole_data.boundary_grants bg
        UNION ALL
        SELECT 'keys'::text,pg_catalog.to_jsonb(k) FROM wormhole_data.keys k
        UNION ALL
        SELECT 'key_copies'::text,pg_catalog.to_jsonb(kc) FROM wormhole_data.key_copies kc
        UNION ALL
        SELECT 'user_key_states'::text,pg_catalog.to_jsonb(uks) FROM wormhole_data.user_key_states uks
        UNION ALL
        SELECT 'user_key_wraps'::text,pg_catalog.to_jsonb(ukw) FROM wormhole_data.user_key_wraps ukw
        UNION ALL
        SELECT 'user_enrollments'::text,pg_catalog.to_jsonb(ue) FROM wormhole_data.user_enrollments ue
        UNION ALL
        SELECT 'nodes'::text,pg_catalog.to_jsonb(n) FROM wormhole_data.nodes n
        UNION ALL
        SELECT 'grants'::text,pg_catalog.to_jsonb(ng) FROM wormhole_data.grants ng
        UNION ALL
        SELECT 'credential_profiles'::text,pg_catalog.to_jsonb(cp) FROM wormhole_data.credential_profiles cp
        UNION ALL
        SELECT 'credential_slots'::text,pg_catalog.to_jsonb(cs) FROM wormhole_data.credential_slots cs
        UNION ALL
        SELECT 'credential_slot_values'::text,pg_catalog.to_jsonb(csv) FROM wormhole_data.credential_slot_values csv
        UNION ALL
        SELECT 'user_node_overrides'::text,pg_catalog.to_jsonb(uno) FROM wormhole_data.user_node_overrides uno
        UNION ALL
        SELECT 'tunnel_profiles'::text,pg_catalog.to_jsonb(tp) FROM wormhole_data.tunnel_profiles tp
        UNION ALL
        SELECT 'node_secret_manifests'::text,pg_catalog.to_jsonb(nsm) FROM wormhole_data.node_secret_manifests nsm
        UNION ALL
        SELECT 'secret_values'::text,pg_catalog.to_jsonb(sv) FROM wormhole_data.secret_values sv
        UNION ALL
        SELECT 'workspace_bootstrap'::text,pg_catalog.to_jsonb(wb) FROM wormhole_data.workspace_bootstrap wb
        UNION ALL
        SELECT 'workspace_server_ca'::text,pg_catalog.to_jsonb(wca) FROM wormhole_data.workspace_server_ca wca{{IMPORT_EXPORT_ROWS}}
    LOOP
        relation:=item.relation;
        body:=item.body::text;
        records:=records+1;
        total:=total+pg_catalog.octet_length(relation)+pg_catalog.octet_length(body);
        IF records>100000 OR total>44040192 THEN
            RAISE EXCEPTION 'Workspace recovery export exceeds limits' USING ERRCODE='WH022';
        END IF;
        RETURN NEXT;
    END LOOP;
    PERFORM wormhole_data.audit_server_ca(identity.actor,identity.session_id,identity.app_version,
        'export_workspace','recovery_snapshot_released');
END
$export$;
