-- Version 36: current signed security policy in every credential release.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>35 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Private encrypted release preparation. The public caller must derive p_user
-- from device admission, authorize node/account boundaries, and consume the
-- committed audit ticket ONLY AFTER this complete bounded payload is ready.
CREATE OR REPLACE FUNCTION wormhole_data.credential_release_graph(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $graph$
DECLARE metadata jsonb; account record; state jsonb; holder_id uuid; holder_version integer;
        role_name text; profile_row jsonb; field_values jsonb; copies jsonb; roots jsonb:='{}';
        accounts jsonb:='[]'; value record; item record; manifest jsonb;
        root_id uuid; root_version integer; label text; result jsonb; policy bytea;
BEGIN
    metadata:=wormhole_data.connection_snapshot(p_node,p_user,p_epoch,p_change_seq);
    SELECT m.signed_profile INTO STRICT policy FROM wormhole_data.workspace_meta m WHERE m.singleton;
    IF metadata#>>'{plan,credential,kind}'='inline' OR metadata#>>'{plan,tunnelId}'<>'' THEN
        RAISE EXCEPTION 'Inline and tunnel release requires signed field material' USING ERRCODE='0A000';
    END IF;
    SELECT s.* INTO account FROM wormhole_data.user_key_states s WHERE s.user_id=p_user;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    state:=convert_from(account.signed_state,'UTF8')::jsonb;
    holder_id:=(state#>>'{encryption,id}')::uuid;holder_version:=(state#>>'{encryption,version}')::integer;
    IF holder_id IS NULL OR holder_version IS NULL OR holder_version<1 THEN RAISE EXCEPTION 'Account key selection unavailable' USING ERRCODE='WH010'; END IF;
    FOREACH role_name IN ARRAY ARRAY['primary','gateway'] LOOP
        profile_row:=metadata->(CASE role_name WHEN 'primary' THEN 'credential' ELSE 'gateway' END);
        IF profile_row='null'::jsonb THEN CONTINUE; END IF;
        field_values:='[]';copies:='[]';
        SELECT convert_from(decode(b.value->>5,'hex'),'UTF8')::jsonb INTO STRICT manifest
            FROM jsonb_array_elements(metadata->'boundaries') b WHERE b.value->>1=profile_row->>5;
        FOR value IN SELECT * FROM wormhole_data.credential_values((profile_row->>1)::uuid,p_epoch,p_change_seq) LOOP
            root_id:=(manifest#>>'{secret,key,id}')::uuid;root_version:=(manifest#>>'{secret,key,version}')::integer;
            IF NOT EXISTS(SELECT 1 FROM wormhole_data.key_copies c WHERE c.key_id=value.dek_id AND c.key_version=value.dek_version AND c.holder_key_id=root_id AND c.holder_key_version=root_version) THEN
                root_id:=(manifest#>>'{previousSecret,key,id}')::uuid;root_version:=(manifest#>>'{previousSecret,key,version}')::integer;
                IF root_id IS NULL OR root_version IS NULL THEN RAISE EXCEPTION 'DEK copy unavailable' USING ERRCODE='WH010'; END IF;
            END IF;
            SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(value.dek_id,value.dek_version,root_id,root_version,p_epoch,p_change_seq);
            copies:=copies||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(item)));
            label:=root_id::text||'/'||root_version::text;
            IF NOT (roots ? label) THEN
                SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq);
                roots:=roots||jsonb_build_object(label,wormhole_data.key_copy_wire(to_jsonb(item)));
            END IF;
            field_values:=field_values||jsonb_build_array(jsonb_build_array(value.workspace_id::text,value.credential_id::text,value.epoch::text,value.change_seq::text,
                value.field,value.row_version::text,value.dek_id::text,value.dek_version::text,encode(value.envelope,'hex')));
        END LOOP;
        accounts:=accounts||jsonb_build_array(jsonb_build_object('account',role_name,'values',field_values,'copies',copies));
    END LOOP;
    result:=jsonb_build_object('formatVersion',2,'profile',encode(policy,'hex'),'metadata',metadata,
        'account',jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')),
        'roots',(SELECT COALESCE(jsonb_agg(r.value ORDER BY r.key COLLATE "C"),'[]'::jsonb) FROM jsonb_each(roots) r),'accounts',accounts);
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'Credential release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$graph$;
REVOKE ALL ON FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=36 WHERE singleton;
COMMIT;
