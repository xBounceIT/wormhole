CREATE FUNCTION wormhole_data.node_note_graph(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $graph$
DECLARE item wormhole_data.nodes; stored wormhole_data.secret_values; author record; account record; enrolled record;
        workspace uuid; policy bytea; projection jsonb; attachment bytea; note jsonb; manifest record; manifest_body jsonb;
        root_label text; previous_label text; root uuid; root_version integer; copy record;
        root_wire jsonb; dek_wire jsonb; value_wire jsonb; boundary_wire jsonb;
BEGIN
    item:=wormhole_data.note_view_target(p_user,p_node);
    SELECT m.workspace_id,m.signed_profile INTO STRICT workspace,policy FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    projection:=wormhole_data.catalog_projection_wire(pg_catalog.to_jsonb(author)||pg_catalog.jsonb_build_object(
        'workspace_id',workspace,'subject_id',p_node,'epoch',p_epoch,'change_seq',p_change_seq,'boundary_id',item.boundary_id,
        'row_version',item.row_version,'seal_suite',item.seal_suite,'seal_signer_key_id',item.seal_signer_key_id,
        'seal_signer_key_version',item.seal_signer_key_version,'seal_capability_id',item.seal_capability_id,
        'seal',item.seal,'record',wormhole_data.node_metadata(item)));
    SELECT s.* INTO STRICT account FROM wormhole_data.user_key_states s WHERE s.user_id=p_user;
    SELECT e.* INTO STRICT enrolled FROM wormhole_data.user_enrollments e WHERE e.user_id=p_user;
    attachment:=wormhole_data.imported_node_body(p_node);
    note:=pg_catalog.convert_from(attachment,'UTF8')::jsonb;
    IF note->>'noteVersion'='1' THEN
        SELECT v.* INTO stored FROM wormhole_data.secret_values v
            WHERE v.owner_kind='node' AND v.owner_id=p_node AND v.field='notes';
        IF NOT FOUND OR stored.row_version<>1 OR octet_length(stored.envelope)>90000 THEN
            RAISE EXCEPTION 'Node note unavailable' USING ERRCODE='WH010';
        END IF;
        SELECT * INTO STRICT manifest FROM wormhole_data.boundary_manifest(item.boundary_id,p_epoch,p_change_seq);
        manifest_body:=pg_catalog.convert_from(manifest.body,'UTF8')::jsonb;
        boundary_wire:=pg_catalog.jsonb_build_array(manifest.workspace_id::text,manifest.boundary_id::text,
            manifest.epoch::text,manifest.change_seq::text,manifest.version::text,encode(manifest.body,'hex'),
            manifest.signer_key_id::text,manifest.signer_key_version::text,encode(manifest.signature,'hex'));
        CASE note->>'formatVersion'
            WHEN '1' THEN root_label:='secret';previous_label:='previousSecret';
            WHEN '2' THEN root_label:='view';previous_label:='previousView';
            ELSE RAISE EXCEPTION 'Unsupported node note' USING ERRCODE='WH025';
        END CASE;
        root:=(manifest_body#>>ARRAY[root_label,'key','id'])::uuid;
        root_version:=(manifest_body#>>ARRAY[root_label,'key','version'])::integer;
        IF NOT EXISTS (SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)
            =(stored.dek_id,stored.dek_version,root,root_version)) THEN
            root:=(manifest_body#>>ARRAY[previous_label,'key','id'])::uuid;
            root_version:=(manifest_body#>>ARRAY[previous_label,'key','version'])::integer;
        END IF;
        IF root IS NULL OR root_version IS NULL THEN RAISE EXCEPTION 'Node note unavailable' USING ERRCODE='WH010'; END IF;
{{NOTE_BOUNDARY_ROOT}}
        SELECT * INTO STRICT copy FROM wormhole_data.key_copy_record(stored.dek_id,stored.dek_version,root,root_version,p_epoch,p_change_seq);
        dek_wire:=wormhole_data.key_copy_wire(pg_catalog.to_jsonb(copy));
        value_wire:=pg_catalog.jsonb_build_array(workspace::text,p_node::text,p_epoch::text,p_change_seq::text,
            'notes',stored.row_version::text,stored.dek_id::text,stored.dek_version::text,encode(stored.envelope,'hex'));
    END IF;
    RETURN pg_catalog.jsonb_build_object('formatVersion',1,'node',projection,
        'attachment',CASE WHEN NOT item.imported ? 'noteVersion' THEN encode(attachment,'hex') END,
        'profile',encode(policy,'hex'),'account',pg_catalog.jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')),
        'enrollment',encode(enrolled.certificate,'hex'),'boundary',boundary_wire,'root',root_wire,'dek',dek_wire,'value',value_wire);
END
$graph$;
