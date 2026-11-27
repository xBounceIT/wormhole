            AND (unassigned_slot IS NULL OR slot->>'protocol'=paths[1])
            AND (base#>>'{credential,kind}'<>'slot' OR EXISTS(
                SELECT FROM wormhole_data.credential_slots chosen
                WHERE chosen.id=NULLIF(base#>>'{credential,id}','')::uuid
                    AND (wormhole_data.effective_boundary_permissions(p_actor,chosen.boundary_id)&1)=1))
