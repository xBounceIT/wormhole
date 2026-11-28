-- Version 46: atomic overlap and retirement of the self-hosted workspace CA.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
DO $migration_lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$migration_lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>45 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.workspace_server_ca (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    key_copy jsonb NOT NULL CHECK(pg_catalog.jsonb_typeof(key_copy)='object'
        AND pg_catalog.octet_length(key_copy::text) BETWEEN 1 AND 1024)
);
REVOKE ALL ON TABLE wormhole_data.workspace_server_ca FROM PUBLIC;

CREATE FUNCTION wormhole_data.require_server_ca_admin(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,p_write boolean)
RETURNS TABLE(actor uuid,session_id uuid,app_version text,bundle jsonb)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $authorize$
DECLARE identity record; meta record; account jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.is_admin AND NOT u.disabled) THEN
        RAISE EXCEPTION 'Workspace administrator required' USING ERRCODE='WH020';
    END IF;
    IF p_write THEN
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    END IF;
    IF meta.state<>'ready' OR NOT meta.require_tls OR NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false)
       OR meta.tls_sequence<1 OR meta.tls_sequence IS DISTINCT FROM p_tls_sequence
       OR pg_catalog.sha256(meta.tls_bundle) IS DISTINCT FROM p_tls_digest
       OR pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM p_profile_digest THEN
        RAISE EXCEPTION 'Workspace TLS state changed' USING ERRCODE='WH011';
    END IF;
    IF COALESCE(pg_catalog.convert_from(meta.signed_profile,'UTF8')::jsonb #>> '{policy,profile}','')
        NOT IN ('default','standard') THEN
        RAISE EXCEPTION 'Workspace profile requires a CA custodian' USING ERRCODE='WH020';
    END IF;
    SELECT pg_catalog.convert_from(a.signed_state,'UTF8')::jsonb INTO account
    FROM wormhole_data.user_key_states a WHERE a.user_id=identity.user_id
        AND pg_catalog.sha256(a.signed_state)=p_account_digest FOR SHARE NOWAIT;
    IF NOT FOUND OR account->>'active' IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'Workspace account state changed' USING ERRCODE='WH010';
    END IF;
    PERFORM 1 FROM wormhole_data.user_enrollments e WHERE e.user_id=identity.user_id
        AND (e.encryption_key_id,e.encryption_key_version)=(p_holder,p_holder_version)
        AND (e.signing_key_id,e.signing_key_version)=(p_signer,p_signer_version) FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace account state changed' USING ERRCODE='WH010';
    END IF;
    RETURN QUERY SELECT identity.user_id,s.id,s.app_version,pg_catalog.convert_from(meta.tls_bundle,'UTF8')::jsonb
        FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
        WHERE a.device_id=identity.device_id;
END
$authorize$;

CREATE FUNCTION wormhole_data.server_ca_key_copy(p_bundle jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
AS $ca$
DECLARE result jsonb;
BEGIN
    IF p_bundle->>'formatVersion'='2' THEN
        SELECT c.key_copy INTO result FROM wormhole_data.workspace_server_ca c WHERE c.singleton;
        IF result->'key' IS DISTINCT FROM p_bundle#>'{workspaceCa,key}' THEN
            RAISE EXCEPTION 'Workspace issuing CA changed' USING ERRCODE='WH020';
        END IF;
    ELSIF pg_catalog.jsonb_array_length(p_bundle->'cas')=1 THEN
        SELECT pg_catalog.convert_from(b.recovery_capsule,'UTF8')::jsonb->'ca' INTO result
            FROM wormhole_data.workspace_bootstrap b WHERE b.singleton;
    END IF;
    IF pg_catalog.jsonb_typeof(result) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'Workspace issuing CA unavailable' USING ERRCODE='WH020';
    END IF;
    RETURN result;
END
$ca$;

CREATE FUNCTION wormhole_data.server_ca_org_copy(p_actor uuid,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_kind text)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
AS $copy$
BEGIN
    RETURN QUERY SELECT k.key_id,k.key_version,c.enc,c.ciphertext,c.signature
    FROM wormhole_data.key_copies c
    JOIN wormhole_data.keys k USING (key_id,key_version)
    JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
    JOIN wormhole_data.keys s ON (s.key_id,s.key_version)=(c.issuer_key_id,c.issuer_key_version)
    WHERE k.kind=p_kind AND k.owner_id IS NULL AND k.status='active'
      AND h.kind='user-enc' AND h.owner_id=p_actor AND h.status='active'
      AND s.kind='user-sign' AND s.owner_id=p_actor AND s.status='active'
      AND (h.key_id,h.key_version)=(p_holder,p_holder_version)
      AND (s.key_id,s.key_version)=(p_signer,p_signer_version)
      AND c.suite=2 AND pg_catalog.octet_length(c.enc)=32 AND pg_catalog.octet_length(c.ciphertext)=48
    FOR SHARE OF k,h,s,c NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace administrator key copy unavailable' USING ERRCODE='WH020';
    END IF;
END
$copy$;

CREATE FUNCTION wormhole_data.audit_server_ca(p_actor uuid,p_session uuid,p_app_version text,p_action text,p_outcome text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
AS $audit$
BEGIN
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
    VALUES(p_actor,p_session,session_user,'ui',p_action,p_outcome,pg_catalog.inet_client_addr(),p_app_version);
END
$audit$;

CREATE OR REPLACE FUNCTION wormhole_api_v1.server_certificate_renewal(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,ca jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $renewal$
DECLARE identity record; key_copy jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    IF identity.bundle#>>'{workspaceCa,previousCa}' IS NOT NULL THEN
        RAISE EXCEPTION 'Server CA rotation in progress' USING ERRCODE='WH020';
    END IF;
    key_copy:=wormhole_data.server_ca_key_copy(identity.bundle);
    RETURN QUERY SELECT c.*,key_copy FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc') c;
    PERFORM wormhole_data.audit_server_ca(identity.actor,identity.session_id,identity.app_version,
        'server_certificate_renewal','key_copy_released');
END
$renewal$;

CREATE FUNCTION wormhole_api_v1.server_ca_rotation_material(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea)
RETURNS TABLE(kind text,org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,ca jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE identity record; key_copy jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    key_copy:=wormhole_data.server_ca_key_copy(identity.bundle);
    RETURN QUERY SELECT 'org-enc'::text,c.*,key_copy FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc') c;
    RETURN QUERY SELECT 'org-sign'::text,c.*,NULL::jsonb FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign') c;
    PERFORM wormhole_data.audit_server_ca(identity.actor,identity.session_id,identity.app_version,
        'server_ca_rotation','key_copies_released');
END
$material$;

CREATE FUNCTION wormhole_api_v1.publish_server_ca_rotation(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_bundle bytea,p_key_copy jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $publish$
DECLARE identity record; current jsonb; incoming jsonb; authority jsonb;
        old_root jsonb; issuer jsonb; action text;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,true);
    current:=identity.bundle;
    PERFORM wormhole_data.server_ca_key_copy(current);
    PERFORM 1 FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc');
    PERFORM 1 FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-sign');
    IF p_tls_sequence=9223372036854775807 OR p_bundle IS NULL OR octet_length(p_bundle) NOT BETWEEN 1 AND 1048576 THEN
        RAISE EXCEPTION 'Invalid workspace CA update' USING ERRCODE='WH021';
    END IF;
    incoming:=pg_catalog.convert_from(p_bundle,'UTF8')::jsonb;
    authority:=incoming->'workspaceCa';
    IF incoming->>'formatVersion' IS DISTINCT FROM '2' OR incoming->>'workspaceId' IS DISTINCT FROM '{{WORKSPACE_ID}}'
        OR current->'signer' IS DISTINCT FROM incoming->'signer'
        OR current->'hosts' IS DISTINCT FROM incoming->'hosts'
        OR current->'revoked' IS DISTINCT FROM incoming->'revoked'
        OR incoming->>'sequence' IS DISTINCT FROM (p_tls_sequence+1)::text
        OR pg_catalog.jsonb_typeof(incoming->'cas') IS DISTINCT FROM 'array'
        OR pg_catalog.jsonb_typeof(authority) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'Invalid workspace CA update' USING ERRCODE='WH021';
    END IF;
    SELECT value INTO issuer FROM pg_catalog.jsonb_array_elements(incoming->'cas')
        WHERE pg_catalog.encode(pg_catalog.sha256(pg_catalog.decode(value#>>'{}','base64')),'hex')=authority->>'issuingCa';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace issuing CA unavailable' USING ERRCODE='WH021';
    END IF;
    IF current#>>'{workspaceCa,previousCa}' IS NULL THEN
        old_root:=current->'cas'->0;
        IF pg_catalog.jsonb_array_length(current->'cas')<>1 OR pg_catalog.jsonb_array_length(incoming->'cas')<>2
            OR NOT (incoming->'cas' @> pg_catalog.jsonb_build_array(old_root))
            OR issuer=old_root OR authority->>'previousCa' IS DISTINCT FROM
                pg_catalog.encode(pg_catalog.sha256(pg_catalog.decode(old_root#>>'{}','base64')),'hex')
            OR pg_catalog.jsonb_typeof(authority->'serverCertificate') IS DISTINCT FROM 'string'
            OR p_key_copy IS NULL OR pg_catalog.octet_length(p_key_copy::text)>1024
            OR pg_catalog.jsonb_typeof(p_key_copy->'key') IS DISTINCT FROM 'object'
            OR pg_catalog.jsonb_typeof(p_key_copy->'copy') IS DISTINCT FROM 'object'
            OR authority->'key' IS DISTINCT FROM p_key_copy->'key'
            OR authority->'key'=current#>'{workspaceCa,key}' THEN
            RAISE EXCEPTION 'Invalid workspace CA overlap' USING ERRCODE='WH021';
        END IF;
        INSERT INTO wormhole_data.workspace_server_ca(singleton,key_copy) VALUES(true,p_key_copy)
            ON CONFLICT(singleton) DO UPDATE SET key_copy=EXCLUDED.key_copy;
        action:='publish_overlap';
    ELSE
        IF pg_catalog.jsonb_array_length(incoming->'cas')<>1 OR authority ? 'previousCa' OR authority ? 'serverCertificate'
            OR authority->'issuingCa' IS DISTINCT FROM current#>'{workspaceCa,issuingCa}'
            OR authority->'key' IS DISTINCT FROM current#>'{workspaceCa,key}' OR p_key_copy IS NOT NULL THEN
            RAISE EXCEPTION 'Invalid workspace CA retirement' USING ERRCODE='WH021';
        END IF;
        action:='retire_previous';
    END IF;
    UPDATE wormhole_data.workspace_meta SET tls_sequence=p_tls_sequence+1,tls_bundle=p_bundle WHERE singleton;
    PERFORM wormhole_data.audit_server_ca(identity.actor,identity.session_id,identity.app_version,'server_ca_rotation',action);
    RETURN p_tls_sequence+1;
END
$publish$;

REVOKE ALL ON FUNCTION
    wormhole_data.require_server_ca_admin(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean),
    wormhole_data.server_ca_key_copy(jsonb),
    wormhole_data.server_ca_org_copy(uuid,uuid,integer,uuid,integer,text),
    wormhole_data.audit_server_ca(uuid,uuid,text,text,text),
    wormhole_api_v1.server_ca_rotation_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.publish_server_ca_rotation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,bytea,jsonb)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    wormhole_api_v1.server_ca_rotation_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.publish_server_ca_rotation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,bytea,jsonb)
TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=46 WHERE singleton;
COMMIT;
