-- Version 99: review, assign or clear a signed shared default credential.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>98 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.slot_default(p_capability bytea,p_holder uuid,p_holder_version integer,p_signer uuid,
    p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy bytea,p_state bytea,
    p_slot uuid,p_name text,p_expected bigint,p_previous_seal bytea,p_credential uuid,p_credential_seal bytea,p_signature bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,slot_row jsonb,credential_row jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $slot_default$
DECLARE actor record; slot wormhole_data.credential_slots; credential wormhole_data.credential_profiles;
    public_key bytea; quoted_name text; message text; writing boolean:=p_expected IS NOT NULL;
BEGIN
    IF p_slot IS NULL OR p_slot='00000000-0000-0000-0000-000000000000'::uuid OR p_name IS NULL OR octet_length(p_name)>1024
        OR (NOT writing AND (p_previous_seal IS NOT NULL OR p_credential IS NOT NULL OR p_credential_seal IS NOT NULL OR p_signature IS NOT NULL))
        OR (writing AND (p_expected NOT BETWEEN 1 AND 9223372036854775806 OR octet_length(p_previous_seal) IS DISTINCT FROM 64
            OR octet_length(p_signature) IS DISTINCT FROM 64 OR (p_name='')<>(p_credential IS NULL)
            OR (p_credential IS NULL AND p_credential_seal IS NOT NULL)
            OR (p_credential IS NOT NULL AND octet_length(p_credential_seal) IS DISTINCT FROM 64))) THEN
        RAISE EXCEPTION 'Invalid slot default request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy,p_state,writing);
    IF NOT FOUND OR NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.actor AND u.is_admin AND NOT u.disabled) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
        RETURN;
    END IF;
    SELECT s.* INTO slot FROM wormhole_data.credential_slots s JOIN wormhole_data.boundaries b ON b.id=s.boundary_id
        WHERE s.id=p_slot AND NOT s.deleted AND b.owner_user_id IS NULL AND NOT b.deleted
            AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&21)=21;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
        RETURN;
    END IF;
    IF p_name<>'' THEN
        -- Personal accounts and Bitwarden references belong to individual users.
        SELECT c.* INTO credential FROM wormhole_data.credential_profiles c JOIN wormhole_data.boundaries b ON b.id=c.boundary_id
            WHERE c.owner_user_id IS NULL AND NOT c.deleted AND c.provider='local' AND c.protocol=slot.protocol
                AND c.name COLLATE "C"=p_name COLLATE "C" AND b.owner_user_id IS NULL AND NOT b.deleted
                AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&11)=11;
        IF NOT FOUND THEN
            RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
            RETURN;
        END IF;
    END IF;
    status:='review';
    IF writing THEN
        IF slot.row_version<>p_expected OR slot.seal IS DISTINCT FROM p_previous_seal OR credential.id IS DISTINCT FROM p_credential
            OR credential.seal IS DISTINCT FROM p_credential_seal OR slot.default_credential_id IS NOT DISTINCT FROM p_credential THEN
            RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
            RETURN;
        END IF;
        SELECT decode(convert_from(e.certificate,'UTF8')::jsonb#>>'{rekey,public,signing}','base64') INTO public_key
            FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
            WHERE e.user_id=actor.actor AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
                AND k.owner_id=actor.actor AND k.kind='user-sign' AND k.status='active';
        quoted_name:=replace(replace(replace(replace(replace(to_json(slot.name)::text,'&',E'\\u0026'),'<',E'\\u003c'),'>',E'\\u003e'),chr(8232),E'\\u2028'),chr(8233),E'\\u2029');
        message:=format('{"workspaceId":"{{WORKSPACE_ID}}","boundaryId":"%s","suite":2,"record":{"id":"%s","name":%s,"protocol":"%s","defaultCredentialId":"%s","allowSelfService":%s,"deleted":false},"seal":{"formatVersion":1,"signerKeyId":"%s","signerKeyVersion":%s,"capabilityId":null,"revision":%s,"signature":null}}',
            slot.boundary_id,p_slot,quoted_name,slot.protocol,coalesce(p_credential::text,''),slot.allow_self_service::text,p_signer,p_signer_version,p_expected+1);
        IF wormhole_data.ed25519_verify(public_key,convert_to('wormhole/v1/shared-slot','UTF8')||decode('00','hex')||convert_to(message,'UTF8'),p_signature) IS DISTINCT FROM true THEN
            RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
            RETURN;
        END IF;
        UPDATE wormhole_data.credential_slots SET default_credential_id=p_credential,row_version=p_expected+1,
            seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_signature WHERE id=p_slot;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'set_slot_default','success');
        status:='saved';
    END IF;
    SELECT m.epoch,m.change_seq INTO STRICT epoch,change_seq FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT wormhole_data.catalog_projection_wire(to_jsonb(s)) INTO STRICT slot_row
        FROM wormhole_data.selection_record('slot',p_slot,NULL,epoch,change_seq) s;
    IF credential.id IS NOT NULL THEN
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(c)) INTO STRICT credential_row
            FROM wormhole_data.credential_record(credential.id,epoch,change_seq) c;
    END IF;
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb;
END
$slot_default$;
REVOKE ALL ON FUNCTION wormhole_api_v1.slot_default(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.slot_default(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,bytea)
    TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=99 WHERE singleton;
COMMIT;
