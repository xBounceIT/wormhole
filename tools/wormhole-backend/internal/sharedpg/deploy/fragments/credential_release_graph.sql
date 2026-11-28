CREATE OR REPLACE FUNCTION wormhole_data.credential_release_graph(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint{{PATH_PARAMETER}})
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $graph$
DECLARE metadata jsonb; account record; enrolled record; enrollment_certificate bytea; state jsonb; holder_id uuid; holder_version integer;
        role_name text; profile_row jsonb; field_values jsonb; copies jsonb; roots jsonb:='{}';
        accounts jsonb:='[]'; value record; item record; manifest jsonb;
        root_id uuid; root_version integer; label text; result jsonb; policy bytea;
        inline_choice boolean; node_fields jsonb; owner_kind text; release_role text;
BEGIN
    metadata:=wormhole_data.connection_snapshot(p_node,p_user,p_epoch,p_change_seq{{PATH_ARG}});
    SELECT m.signed_profile INTO STRICT policy FROM wormhole_data.workspace_meta m WHERE m.singleton;
    inline_choice:=metadata#>>'{plan,credential,kind}'='inline';
    IF inline_choice THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('node-fields',p_node,NULL,p_epoch,p_change_seq);
        node_fields:=wormhole_data.catalog_projection_wire(to_jsonb(item));
    END IF;
    SELECT s.* INTO account FROM wormhole_data.user_key_states s WHERE s.user_id=p_user;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    state:=convert_from(account.signed_state,'UTF8')::jsonb;
    SELECT e.* INTO enrolled FROM wormhole_data.user_enrollments e WHERE e.user_id=p_user;
    IF FOUND THEN
        holder_id:=enrolled.encryption_key_id;holder_version:=enrolled.encryption_key_version;
        enrollment_certificate:=enrolled.certificate;
    ELSE
        holder_id:=(state#>>'{encryption,id}')::uuid;holder_version:=(state#>>'{encryption,version}')::integer;
    END IF;
    IF holder_id IS NULL OR holder_version IS NULL OR holder_version<1 THEN RAISE EXCEPTION 'Account key selection unavailable' USING ERRCODE='WH010'; END IF;
    FOREACH role_name IN ARRAY ARRAY['primary','gateway','tunnel'] LOOP
{{SKIP_GATEWAY_ROUTE_VALUES}}        profile_row:=metadata->(CASE role_name WHEN 'primary' THEN 'credential' WHEN 'gateway' THEN 'gateway' ELSE 'tunnel' END);
        owner_kind:='credential';release_role:=role_name;
        IF role_name='primary' AND inline_choice THEN
            profile_row:=node_fields;owner_kind:='node';release_role:='inline';
        END IF;
        IF profile_row IS NULL OR profile_row='null'::jsonb THEN CONTINUE; END IF;
        IF role_name='tunnel' THEN owner_kind:='tunnel'; END IF;
        field_values:='[]';copies:='[]';
        SELECT convert_from(decode(b.value->>5,'hex'),'UTF8')::jsonb INTO STRICT manifest
            FROM jsonb_array_elements(metadata->'boundaries') b WHERE b.value->>1=profile_row->>5;
        FOR value IN SELECT * FROM wormhole_data.owner_values(owner_kind,(profile_row->>1)::uuid,p_epoch,p_change_seq) LOOP
            root_id:=(manifest#>>'{secret,key,id}')::uuid;root_version:=(manifest#>>'{secret,key,version}')::integer;
            IF NOT EXISTS(SELECT 1 FROM wormhole_data.key_copies c WHERE c.key_id=value.dek_id AND c.key_version=value.dek_version AND c.holder_key_id=root_id AND c.holder_key_version=root_version) THEN
                root_id:=(manifest#>>'{previousSecret,key,id}')::uuid;root_version:=(manifest#>>'{previousSecret,key,version}')::integer;
                IF root_id IS NULL OR root_version IS NULL THEN RAISE EXCEPTION 'DEK copy unavailable' USING ERRCODE='WH010'; END IF;
            END IF;
            SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(value.dek_id,value.dek_version,root_id,root_version,p_epoch,p_change_seq);
            copies:=copies||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(item)));
            label:=root_id::text||'/'||root_version::text;
            IF NOT (roots ? label) THEN
{{CREDENTIAL_BOUNDARY_ROOT}}
            END IF;
            field_values:=field_values||jsonb_build_array(jsonb_build_array(value.workspace_id::text,value.owner_id::text,value.epoch::text,value.change_seq::text,
                value.field,value.row_version::text,value.dek_id::text,value.dek_version::text,encode(value.envelope,'hex')));
        END LOOP;
        accounts:=accounts||jsonb_build_array(jsonb_build_object('account',release_role,'values',field_values,'copies',copies));
    END LOOP;
    result:=jsonb_build_object('formatVersion',5,'profile',encode(policy,'hex'),'metadata',metadata,
        'account',jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')),
        'roots',(SELECT COALESCE(jsonb_agg(r.value ORDER BY r.key COLLATE "C"),'[]'::jsonb) FROM jsonb_each(roots) r),'accounts',accounts);
    result:=result||jsonb_build_object('nodeFields',node_fields,'enrollment',encode(enrollment_certificate,'hex'));
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'Credential release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$graph$;
