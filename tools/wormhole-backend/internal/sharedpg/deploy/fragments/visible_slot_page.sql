    -- Apply View before pagination so the cursor cannot reveal private slots.
    FOR candidate IN SELECT s.id FROM wormhole_data.credential_slots s
            WHERE NOT s.deleted AND (p_after IS NULL OR s.id>p_after)
                AND (wormhole_data.effective_boundary_permissions(actor.user_id,s.boundary_id)&1)=1
            ORDER BY s.id LIMIT 26 LOOP
        IF count_rows=25 THEN outcome:='more'; EXIT; END IF;
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(r)) INTO STRICT wire
            FROM wormhole_data.selection_record('slot',candidate,NULL,meta.epoch,meta.change_seq) r;
        wire_bytes:=octet_length(wire::text)+2;
        -- An enrolled author proof alone may exceed the normal page budget.
        -- Admit one full row so a supported certificate always makes progress.
        IF count_rows>0 AND page_bytes+wire_bytes>786432 THEN outcome:='more'; EXIT; END IF;
        items:=items||jsonb_build_array(wire);
        page_bytes:=page_bytes+wire_bytes;
        count_rows:=count_rows+1;
    END LOOP;
    RETURN QUERY SELECT outcome,meta.epoch,meta.change_seq,items;
