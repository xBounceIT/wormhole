CREATE {{REPLACE_READ}}FUNCTION wormhole_api_v1.read_node_edit(p_capability bytea,p_node uuid,p_revision bigint,p_policy bytea,p_state bytea)
RETURNS TABLE(status text,node_row jsonb,field_row jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $read$
DECLARE actor record; meta wormhole_data.workspace_meta; n wormhole_data.nodes; mask integer;
BEGIN
    IF p_node IS NULL OR p_revision IS NULL OR p_revision<1 OR octet_length(p_policy) IS DISTINCT FROM 32
        OR octet_length(p_state) IS DISTINCT FROM 32 THEN RAISE EXCEPTION 'Invalid node edit' USING ERRCODE='22023'; END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR
        NOT EXISTS(SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id AND sha256(s.signed_state)=p_state
            AND convert_from(s.signed_state,'UTF8')::jsonb->'active'='true'::jsonb) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb,NULL::jsonb; RETURN;
    END IF;
    SELECT * INTO n FROM wormhole_data.nodes WHERE id=p_node;
    IF FOUND THEN mask:=wormhole_data.effective_permissions(actor.user_id,p_node); END IF;
    IF mask IS NULL OR (mask&5)<>5 OR n.seal IS NULL OR n.encrypted_metadata IS NOT NULL THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb,NULL::jsonb; RETURN;
    END IF;
    IF n.row_version<>p_revision THEN RETURN QUERY SELECT 'stale'::text,NULL::jsonb,NULL::jsonb; RETURN; END IF;
    node_row:=jsonb_build_array(meta.workspace_id::text,actor.user_id::text,meta.epoch::text,meta.change_seq::text,'1','false',
        wormhole_data.node_metadata(n)::text,mask::text,n.boundary_id::text,n.row_version::text,n.seal_suite::text,
        n.seal_signer_key_id::text,n.seal_signer_key_version::text,n.seal_capability_id::text,encode(n.seal,'hex'));
    IF EXISTS(SELECT FROM wormhole_data.node_secret_manifests WHERE node_id=p_node) THEN
{{READ_FIELD_ROW}}
    END IF;
    status:='ready'; RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN RETURN QUERY SELECT 'busy'::text,NULL::jsonb,NULL::jsonb;
END
$read$;
