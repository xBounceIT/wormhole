CREATE{{FALLBACK_REPLACE}} FUNCTION wormhole_data.fallback_release_graph(p_node uuid,p_user uuid,p_primary uuid,p_fallback uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $graph$
DECLARE source jsonb; target record; item record; value record; boundary record;
        manifest jsonb; account record; enrolled record; state jsonb;
        holder_id uuid; holder_version integer; root_id uuid; root_version integer;
        field_values jsonb:='[]'; copies jsonb:='[]'; roots jsonb:='{}'; label text; result jsonb;
BEGIN
{{FALLBACK_PATH_GRAPH}}
    IF source#>>'{metadata,plan,tunnelId}' IS DISTINCT FROM p_primary::text THEN
        RAISE EXCEPTION 'Fallback source changed' USING ERRCODE='WH013';
    END IF;
    SELECT * INTO STRICT target FROM wormhole_data.selection_record('tunnel',p_fallback,NULL,p_epoch,p_change_seq);
    IF (target.record#>>'{metadata,kind}')::integer<>2 OR (target.record->>'deleted')::boolean THEN
        RAISE EXCEPTION 'Fallback unavailable' USING ERRCODE='WH018';
    END IF;
    SELECT * INTO STRICT boundary FROM wormhole_data.boundary_manifest(target.boundary_id,p_epoch,p_change_seq);
    manifest:=convert_from(boundary.body,'UTF8')::jsonb;
    SELECT s.* INTO STRICT account FROM wormhole_data.user_key_states s WHERE s.user_id=p_user;
    state:=convert_from(account.signed_state,'UTF8')::jsonb;
    SELECT e.* INTO enrolled FROM wormhole_data.user_enrollments e WHERE e.user_id=p_user;
    IF FOUND THEN
        holder_id:=enrolled.encryption_key_id;holder_version:=enrolled.encryption_key_version;
    ELSE
        holder_id:=(state#>>'{encryption,id}')::uuid;holder_version:=(state#>>'{encryption,version}')::integer;
    END IF;
    IF holder_id IS NULL OR holder_version IS NULL OR holder_version<1 THEN
        RAISE EXCEPTION 'Account key selection unavailable' USING ERRCODE='WH010';
    END IF;
    FOR value IN SELECT * FROM wormhole_data.owner_values('tunnel',p_fallback,p_epoch,p_change_seq) LOOP
        root_id:=(manifest#>>'{secret,key,id}')::uuid;root_version:=(manifest#>>'{secret,key,version}')::integer;
        IF NOT EXISTS(SELECT 1 FROM wormhole_data.key_copies c WHERE c.key_id=value.dek_id AND c.key_version=value.dek_version AND c.holder_key_id=root_id AND c.holder_key_version=root_version) THEN
            root_id:=(manifest#>>'{previousSecret,key,id}')::uuid;root_version:=(manifest#>>'{previousSecret,key,version}')::integer;
            IF root_id IS NULL OR root_version IS NULL THEN RAISE EXCEPTION 'DEK copy unavailable' USING ERRCODE='WH010'; END IF;
        END IF;
        SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(value.dek_id,value.dek_version,root_id,root_version,p_epoch,p_change_seq);
        copies:=copies||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(item)));
        label:=root_id::text||'/'||root_version::text;
        IF NOT (roots ? label) THEN
{{FALLBACK_BOUNDARY_ROOT}}
        END IF;
        field_values:=field_values||jsonb_build_array(jsonb_build_array(value.workspace_id::text,value.owner_id::text,value.epoch::text,value.change_seq::text,
            value.field,value.row_version::text,value.dek_id::text,value.dek_version::text,encode(value.envelope,'hex')));
    END LOOP;
    result:=jsonb_build_object('formatVersion',1,'source',source,
        'target',wormhole_data.catalog_projection_wire(to_jsonb(target)),
        'boundary',jsonb_build_array(boundary.workspace_id::text,boundary.boundary_id::text,boundary.epoch::text,boundary.change_seq::text,
            boundary.version::text,encode(boundary.body,'hex'),boundary.signer_key_id::text,boundary.signer_key_version::text,encode(boundary.signature,'hex')),
        'values',field_values,'copies',copies,
        'roots',(SELECT COALESCE(jsonb_agg(r.value ORDER BY r.key COLLATE "C"),'[]'::jsonb) FROM jsonb_each(roots) r));
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'Fallback release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$graph$;
