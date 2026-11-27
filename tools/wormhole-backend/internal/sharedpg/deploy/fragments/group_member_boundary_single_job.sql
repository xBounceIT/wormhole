    SELECT * INTO STRICT retained FROM wormhole_data.group_key_roster(job.group_id);
    roster_raw:=coalesce(retained.body,convert_to('[]','UTF8'));
    IF retained.status NOT IN ('ready','no-members') OR updated_group->>'rosterDigest' IS DISTINCT FROM
        encode(wormhole_data.group_key_review(job.group_id,job.group_revision,roster_raw),'base64') THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT g.permissions INTO group_mask FROM wormhole_data.boundary_grants g WHERE g.boundary_id=p_boundary AND g.group_id=job.group_id FOR SHARE NOWAIT;
    rotation_graph:=wormhole_data.boundary_rotation_graph(p_boundary,job.group_id,mask,old,recipient.key_id,recipient.key_version,meta.epoch,meta.change_seq);
    replacement:=jsonb_build_object('kind','group','subject',job.group_id,'key',updated_group#>'{key,key}',
        'manifest',encode(team.key_manifest,'hex'),'proof',convert_from(roster_raw,'UTF8'));
    next_graph:='[]';
    FOR root IN SELECT value FROM jsonb_array_elements(rotation_graph) LOOP
        purpose:=CASE WHEN root->>'purpose'='view' THEN 1 ELSE 2 END;
        IF retained.status='ready' AND (COALESCE(group_mask,0)&purpose)=purpose THEN
            root:=jsonb_set(root,'{recipients}',(root->'recipients')||jsonb_build_array(replacement));
        END IF;
        next_graph:=next_graph||jsonb_build_array(root);
    END LOOP;
