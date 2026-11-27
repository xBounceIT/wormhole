-- Version 38: current public policy/account state for native activation/monitoring.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>37 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.runtime_state(p_capability bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $state$
DECLARE identity record; meta record; account record; result jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    SELECT s.* INTO account FROM wormhole_data.user_key_states s WHERE s.user_id=identity.user_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    result:=jsonb_build_object('formatVersion',1,'profile',encode(meta.signed_profile,'hex'),
        'account',jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')));
    IF octet_length(result::text)>262144 THEN RAISE EXCEPTION 'Runtime state is too large' USING ERRCODE='54000'; END IF;
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,meta.epoch,meta.change_seq,result;
END
$state$;
REVOKE ALL ON FUNCTION wormhole_api_v1.runtime_state(bytea) FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.runtime_state(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=38 WHERE singleton;
COMMIT;
