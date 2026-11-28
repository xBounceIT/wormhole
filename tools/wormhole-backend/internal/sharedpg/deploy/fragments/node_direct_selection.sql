    -- An empty folder has no resolved leaves. Check the directly selected slot
    -- as well. A connection with its own password cannot change its dormant
    -- credential selection. The caller compares these fields before and after
    -- the edit, so unrelated changes and removal of obsolete slots still work.
    RETURN QUERY SELECT n.id::text||'/selection',
        sha256(convert_to(jsonb_build_array(n.credential_mode,n.credential_id,n.credential_slot_id)::text,'UTF8')),
        n.use_inline_password IS NOT TRUE AND EXISTS(
            SELECT FROM wormhole_data.credential_slots s WHERE s.id=n.credential_slot_id AND NOT s.deleted
                AND (wormhole_data.effective_boundary_permissions(p_actor,s.boundary_id)&1)=1)
        FROM wormhole_data.nodes n WHERE n.id=p_root AND (n.credential_slot_id IS NOT NULL OR n.use_inline_password IS TRUE);
