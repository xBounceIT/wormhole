CREATE{{FALLBACK_REPLACE}} FUNCTION wormhole_data.fallback_permissions(p_capability bytea,p_node uuid,p_primary uuid,p_fallback uuid,p_epoch bigint,p_change_seq bigint)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $permissions$
DECLARE identity record; plan jsonb; target_boundary uuid;
BEGIN
    IF p_primary IS NULL OR p_fallback IS NULL OR p_primary=p_fallback
       OR p_primary='00000000-0000-0000-0000-000000000000'::uuid
       OR p_fallback='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid fallback request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
{{FALLBACK_PATH_PLAN}}
    IF plan->>'tunnelId' IS DISTINCT FROM p_primary::text
       OR NOT EXISTS(SELECT 1 FROM wormhole_data.tunnel_profiles t WHERE t.id=p_primary AND t.kind=9 AND NOT t.deleted) THEN
        RAISE EXCEPTION 'Fallback permission required' USING ERRCODE='42501';
    END IF;
    SELECT t.boundary_id INTO target_boundary FROM wormhole_data.tunnel_profiles t WHERE t.id=p_fallback AND t.kind=2 AND NOT t.deleted;
    IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&2)<>2 THEN
        RAISE EXCEPTION 'Fallback permission required' USING ERRCODE='42501';
    END IF;
END
$permissions$;
