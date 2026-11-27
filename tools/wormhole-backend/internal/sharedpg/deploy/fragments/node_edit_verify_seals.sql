    SELECT decode(convert_from(e.certificate,'UTF8')::jsonb#>>'{rekey,public,signing}','base64') INTO public_key
        FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
        WHERE e.user_id=actor.user_id AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
          AND k.owner_id=actor.user_id AND k.kind='user-sign' AND k.status='active';
    IF NOT wormhole_data.ed25519_verify(public_key,wormhole_data.node_edit_message(meta.workspace_id,original.boundary_id,p_metadata,NULL,
            p_signer,p_signer_version,p_revision+1),p_seal) OR (has_fields AND NOT wormhole_data.ed25519_verify(public_key,
            wormhole_data.node_edit_message(meta.workspace_id,original.boundary_id,p_metadata,fields.fields,p_signer,p_signer_version,p_revision+1),p_fields_seal)) THEN
        RETURN 'unavailable';
    END IF;
