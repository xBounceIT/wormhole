-- Version 95: create a signed, initially unassigned workspace credential slot.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>94 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.create_credential_slot(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,
    p_state_digest bytea,p_id uuid,p_name text,p_protocol text,p_self_service boolean,p_boundary uuid,
    p_manifest_digest bytea,p_signature bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $create_slot$
DECLARE actor record; manifest bytea; public_key bytea; quoted_name text; message text; stored wormhole_data.credential_slots;
BEGIN
    IF p_id IS NULL OR p_id='00000000-0000-0000-0000-000000000000'::uuid OR p_boundary IS NULL
        OR coalesce(octet_length(p_name),0) NOT BETWEEN 1 AND 1024 OR p_name ~ '[[:cntrl:]]'
        OR wormhole_data.resolver_text(p_name)='' OR p_protocol IS NULL OR p_protocol NOT IN ('ssh','rdp','vnc')
        OR p_self_service IS NULL OR octet_length(p_signature) IS DISTINCT FROM 64
        OR octet_length(p_manifest_digest) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid credential slot' USING ERRCODE='22023';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND OR NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.actor AND u.is_admin AND NOT u.disabled)
        OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&21)<>21 THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT m.body INTO manifest FROM wormhole_data.boundary_manifests m JOIN wormhole_data.boundaries b ON b.id=m.boundary_id
        WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE OF m,b NOWAIT;
    IF sha256(manifest) IS DISTINCT FROM p_manifest_digest THEN
        RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT decode(convert_from(e.certificate,'UTF8')::jsonb#>>'{rekey,public,signing}','base64') INTO public_key
        FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
        WHERE e.user_id=actor.actor AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
          AND k.owner_id=actor.actor AND k.kind='user-sign' AND k.status='active';
    -- Keep the field order and escaping of the format-1 Go SlotRecord.
    quoted_name:=replace(replace(replace(replace(replace(to_json(p_name)::text,'&',E'\\u0026'),'<',E'\\u003c'),'>',E'\\u003e'),chr(8232),E'\\u2028'),chr(8233),E'\\u2029');
    message:=format('{"workspaceId":"{{WORKSPACE_ID}}","boundaryId":"%s","suite":2,"record":{"id":"%s","name":%s,"protocol":"%s","defaultCredentialId":"","allowSelfService":%s,"deleted":false},"seal":{"formatVersion":1,"signerKeyId":"%s","signerKeyVersion":%s,"capabilityId":null,"revision":1,"signature":null}}',
        p_boundary,p_id,quoted_name,p_protocol,p_self_service::text,p_signer,p_signer_version);
    IF wormhole_data.ed25519_verify(public_key,convert_to('wormhole/v1/shared-slot','UTF8')||decode('00','hex')||convert_to(message,'UTF8'),p_signature) IS DISTINCT FROM true THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT * INTO stored FROM wormhole_data.credential_slots WHERE id=p_id FOR UPDATE NOWAIT;
    IF NOT FOUND THEN
        INSERT INTO wormhole_data.credential_slots(id,name,protocol,allow_self_service,boundary_id,seal_suite,
            seal_signer_key_id,seal_signer_key_version,seal)
        VALUES(p_id,p_name,p_protocol,p_self_service,p_boundary,2,p_signer,p_signer_version,p_signature);
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'create_credential_slot','success');
    ELSIF stored.boundary_id<>p_boundary OR stored.row_version<>1 OR stored.deleted OR stored.default_credential_id IS NOT NULL
        OR stored.name COLLATE "C"<>p_name OR stored.protocol<>p_protocol OR stored.allow_self_service<>p_self_service
        OR (stored.seal_signer_key_id,stored.seal_signer_key_version)<>(p_signer,p_signer_version) OR stored.seal<>p_signature THEN
        RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    RETURN QUERY SELECT 'saved'::text,m.epoch,m.change_seq,wormhole_data.catalog_projection_wire(to_jsonb(r))
        FROM wormhole_data.workspace_meta m CROSS JOIN LATERAL wormhole_data.selection_record('slot',p_id,NULL,m.epoch,m.change_seq) r
        WHERE m.singleton;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
END
$create_slot$;
REVOKE ALL ON FUNCTION wormhole_api_v1.create_credential_slot(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,boolean,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.create_credential_slot(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,boolean,uuid,bytea,bytea)
    TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=95 WHERE singleton;
COMMIT;
