-- Version 100: an enrolled user can assign a personal credential to a self-service slot.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>99 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.personal_slot_value(p_capability bytea,p_holder uuid,p_holder_version integer,p_signer uuid,
    p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy bytea,p_state bytea,
    p_slot uuid,p_name text,p_revision bigint,p_slot_seal bytea,p_value uuid,p_value_seal bytea,
    p_credential uuid,p_credential_seal bytea,p_signature bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,slot_row jsonb,value_row jsonb,credential_row jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $personal_slot$
DECLARE actor record; slot wormhole_data.credential_slots; assignment wormhole_data.credential_slot_values;
    credential wormhole_data.credential_profiles; personal uuid; public_key bytea; message text;
    writing boolean:=p_revision IS NOT NULL;
BEGIN
    IF p_slot IS NULL OR p_slot='00000000-0000-0000-0000-000000000000'::uuid OR p_name IS NULL OR octet_length(p_name)>1024
        OR (NOT writing AND (p_slot_seal IS NOT NULL OR p_value IS NOT NULL OR p_value_seal IS NOT NULL
            OR p_credential IS NOT NULL OR p_credential_seal IS NOT NULL OR p_signature IS NOT NULL))
        OR (writing AND (p_revision NOT BETWEEN 0 AND 9223372036854775806 OR p_value IS NULL OR p_value='00000000-0000-0000-0000-000000000000'::uuid
            OR octet_length(p_signature) IS DISTINCT FROM 64 OR octet_length(p_slot_seal) IS DISTINCT FROM 64
            OR (p_revision=0 AND p_value_seal IS NOT NULL) OR (p_revision>0 AND octet_length(p_value_seal) IS DISTINCT FROM 64)
            OR (p_name='')<>(p_credential IS NULL) OR (p_credential IS NULL AND p_credential_seal IS NOT NULL)
            OR (p_credential IS NOT NULL AND octet_length(p_credential_seal) IS DISTINCT FROM 64))) THEN
        RAISE EXCEPTION 'Invalid personal slot change' USING ERRCODE='22023';
    END IF;
    status:='unavailable';
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy,p_state,writing);
    IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    SELECT s.* INTO slot FROM wormhole_data.credential_slots s JOIN wormhole_data.boundaries b ON b.id=s.boundary_id
        WHERE s.id=p_slot AND s.allow_self_service AND NOT s.deleted AND b.owner_user_id IS NULL AND NOT b.deleted
        AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&3)=3;
    IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    personal:=wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,actor.actor);
    IF NOT EXISTS(SELECT FROM wormhole_data.boundaries b WHERE b.id=personal AND b.owner_user_id=actor.actor AND NOT b.deleted
        AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&7)=7) THEN RETURN NEXT; RETURN; END IF;
    SELECT * INTO assignment FROM wormhole_data.credential_slot_values v WHERE v.slot_id=p_slot AND v.user_id=actor.actor;
    IF FOUND AND assignment.boundary_id<>personal THEN RETURN NEXT; RETURN; END IF;
    IF p_name<>'' THEN
        SELECT * INTO credential FROM wormhole_data.credential_profiles c
            WHERE c.owner_user_id=actor.actor AND c.boundary_id=personal AND NOT c.deleted AND c.protocol=slot.protocol
            AND c.provider IN ('local','bitwarden') AND c.name COLLATE "C"=p_name COLLATE "C";
        IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    END IF;
    status:='review';
    IF writing THEN
        IF p_slot_seal IS DISTINCT FROM slot.seal OR coalesce(assignment.row_version,0)<>p_revision
            OR (assignment.id IS NOT NULL AND assignment.id<>p_value) OR assignment.seal IS DISTINCT FROM p_value_seal
            OR credential.id IS DISTINCT FROM p_credential OR credential.seal IS DISTINCT FROM p_credential_seal
            OR (CASE WHEN assignment.deleted THEN NULL::uuid ELSE assignment.credential_id END) IS NOT DISTINCT FROM p_credential THEN
            status:='stale'; RETURN NEXT; RETURN;
        END IF;
        SELECT decode(convert_from(e.certificate,'UTF8')::jsonb#>>'{rekey,public,signing}','base64') INTO public_key
            FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
            WHERE e.user_id=actor.actor AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
                AND k.owner_id=actor.actor AND k.kind='user-sign' AND k.status='active';
        message:=format('{"workspaceId":"{{WORKSPACE_ID}}","boundaryId":"%s","suite":2,"record":{"id":"%s","slotId":"%s","userId":"%s","credentialId":"%s","deleted":%s},"seal":{"formatVersion":1,"signerKeyId":"%s","signerKeyVersion":%s,"capabilityId":null,"revision":%s,"signature":null}}',
            personal,p_value,p_slot,actor.actor,coalesce(p_credential::text,''),(p_credential IS NULL)::text,p_signer,p_signer_version,p_revision+1);
        IF wormhole_data.ed25519_verify(public_key,convert_to('wormhole/v1/shared-slot-value','UTF8')||decode('00','hex')||convert_to(message,'UTF8'),p_signature) IS DISTINCT FROM true THEN
            status:='unavailable'; RETURN NEXT; RETURN;
        END IF;
        IF assignment.id IS NULL THEN
            INSERT INTO wormhole_data.credential_slot_values(id,slot_id,user_id,credential_id,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
                VALUES(p_value,p_slot,actor.actor,p_credential,personal,2,p_signer,p_signer_version,p_signature);
        ELSE
            UPDATE wormhole_data.credential_slot_values SET credential_id=p_credential,deleted=(p_credential IS NULL),row_version=p_revision+1,
                seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_signature WHERE id=assignment.id;
        END IF;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'set_personal_slot_value','success');
        status:='saved';
    END IF;
    SELECT m.epoch,m.change_seq INTO STRICT epoch,change_seq FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT wormhole_data.catalog_projection_wire(to_jsonb(s)) INTO STRICT slot_row FROM wormhole_data.selection_record('slot',p_slot,NULL,epoch,change_seq) s;
    IF assignment.id IS NOT NULL OR writing THEN
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(v)) INTO STRICT value_row FROM wormhole_data.selection_record('slot-value',p_slot,actor.actor,epoch,change_seq) v;
    END IF;
    IF credential.id IS NOT NULL THEN
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(c)) INTO STRICT credential_row FROM wormhole_data.credential_record(credential.id,epoch,change_seq) c;
    END IF;
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb,NULL::jsonb;
END
$personal_slot$;
REVOKE ALL ON FUNCTION wormhole_api_v1.personal_slot_value(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.personal_slot_value(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,uuid,bytea,bytea) TO wh_{{TAG}}_user;

CREATE FUNCTION wormhole_api_v1.my_credential_slots(p_capability bytea,p_after uuid,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $slots$
DECLARE actor record; meta record; candidate uuid; wire jsonb; items jsonb:='[]'; count_rows integer:=0;
    page_bytes integer:=2; wire_bytes integer; outcome text:='ready';
BEGIN
    IF p_after='00000000-0000-0000-0000-000000000000'::uuid OR octet_length(p_policy) IS DISTINCT FROM 32
        OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid personal slot page' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR NOT meta.require_tls OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() t WHERE t.ssl)
        OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR NOT EXISTS(
        SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id AND sha256(s.signed_state)=p_account_state
            AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE NOWAIT) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
{{VISIBLE_SLOT_PAGE}}
END
$slots$;
REVOKE ALL ON FUNCTION wormhole_api_v1.my_credential_slots(bytea,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.my_credential_slots(bytea,uuid,bytea,bytea) TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=100 WHERE singleton;
COMMIT;
