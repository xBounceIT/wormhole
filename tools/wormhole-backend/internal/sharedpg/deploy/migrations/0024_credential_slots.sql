-- Version 24: metadata-only per-user credential slot resolution.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>23 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Inputs must come from authenticated catalog records in the owning release API.
-- This helper neither authorizes access nor reads/releases secrets.
CREATE FUNCTION wormhole_data.resolve_slot(p_plan jsonb,p_user text,p_slot jsonb,p_value jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $slot$
DECLARE expected text; selected text; choice jsonb;
BEGIN
    expected:=CASE p_plan->>'protocol' WHEN '0' THEN 'ssh' WHEN '7' THEN 'ssh' WHEN '1' THEN 'rdp' WHEN '6' THEN 'vnc' ELSE '' END;
    IF jsonb_typeof(p_plan) IS DISTINCT FROM 'object' OR jsonb_typeof(p_slot) IS DISTINCT FROM 'object'
       OR p_plan->'resolverVersion' IS DISTINCT FROM '1'::jsonb
       OR NOT wormhole_data.resolver_id(p_plan->>'nodeId')
       OR NOT wormhole_data.resolver_id(p_plan#>>'{credential,nodeId}')
       OR NOT wormhole_data.resolver_id(p_user)
       OR p_plan#>>'{credential,kind}' IS DISTINCT FROM 'slot'
       OR NOT wormhole_data.resolver_id(p_slot->>'id')
       OR p_plan#>>'{credential,id}' IS DISTINCT FROM p_slot->>'id'
       OR expected='' OR p_slot->>'protocol' IS DISTINCT FROM expected
       OR jsonb_typeof(p_plan->'protocol') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p_slot->'defaultCredentialId') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_slot->'allowSelfService') IS DISTINCT FROM 'boolean' THEN
        RAISE EXCEPTION 'Invalid credential slot' USING ERRCODE='WH018';
    END IF;
    selected:=p_slot->>'defaultCredentialId';
    IF selected<>'' AND NOT wormhole_data.resolver_id(selected) THEN
        RAISE EXCEPTION 'Invalid credential slot default' USING ERRCODE='WH018';
    END IF;
    IF p_value IS NOT NULL AND p_value<>'null'::jsonb THEN
        IF jsonb_typeof(p_value) IS DISTINCT FROM 'object'
           OR p_value->>'slotId' IS DISTINCT FROM p_slot->>'id'
           OR p_value->>'userId' IS DISTINCT FROM p_user
           OR NOT wormhole_data.resolver_id(p_value->>'credentialId') THEN
            RAISE EXCEPTION 'Invalid credential slot assignment' USING ERRCODE='WH018';
        END IF;
        selected:=p_value->>'credentialId';
    END IF;
    IF selected='' THEN RAISE EXCEPTION 'Credential slot is unassigned' USING ERRCODE='WH018'; END IF;
    choice:=jsonb_build_object('kind','saved','id',selected,'nodeId',p_plan#>>'{credential,nodeId}');
    RETURN p_plan || jsonb_build_object('credential',choice,'username','','domain','');
END
$slot$;
REVOKE ALL ON FUNCTION wormhole_data.resolve_slot(jsonb,text,jsonb,jsonb) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=24 WHERE singleton;
COMMIT;
