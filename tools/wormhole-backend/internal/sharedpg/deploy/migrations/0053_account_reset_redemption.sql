-- Version 53: atomic reset redemption and authenticated reconciliation.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>52 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.account_reset_receipts (
    offer_id uuid PRIMARY KEY REFERENCES wormhole_data.account_reset_offers(id),
    device_id uuid NOT NULL UNIQUE REFERENCES wormhole_data.devices(id),
    wrap_revision bigint NOT NULL CHECK(wrap_revision>=2),
    auth_epoch bigint NOT NULL CHECK(auth_epoch>=1)
);
REVOKE ALL ON TABLE wormhole_data.account_reset_receipts
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

CREATE FUNCTION wormhole_data.require_account_reset(p_offer uuid,p_offer_hash bytea,p_write boolean)
RETURNS wormhole_data.account_reset_offers
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
AS $require$
DECLARE request wormhole_data.account_reset_offers; meta record;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Unsupported workspace transaction isolation' USING ERRCODE='WH006';
    END IF;
    IF p_write THEN
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
        SELECT * INTO request FROM wormhole_data.account_reset_offers r WHERE r.id=p_offer FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
        SELECT * INTO request FROM wormhole_data.account_reset_offers r WHERE r.id=p_offer FOR SHARE NOWAIT;
    END IF;
    IF NOT FOUND OR request.role_name<>session_user OR request.retired_at IS NOT NULL OR
       request.expires_at<=pg_catalog.clock_timestamp() OR request.offer_hash IS DISTINCT FROM p_offer_hash OR
       meta.state<>'ready' OR NOT meta.require_tls OR meta.min_api>1 OR meta.max_api<1 OR
       pg_catalog.sha256(meta.tls_bundle) IS DISTINCT FROM request.tls_hash OR
       pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM request.policy_hash OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) OR
       NOT EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=request.role_oid AND r.rolname=request.role_name AND r.rolcanlogin
          AND r.rolvaliduntil=request.expires_at AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
          AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit)
       OR request.subject IS DISTINCT FROM wormhole_data.account_reset_target(request.subject->>'loginName') THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    RETURN request;
END
$require$;

CREATE OR REPLACE FUNCTION wormhole_api_v1.account_reset_capsule(p_offer uuid,p_offer_hash bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $capsule$
DECLARE request wormhole_data.account_reset_offers;
BEGIN
    request:=wormhole_data.require_account_reset(p_offer,p_offer_hash,false);
    PERFORM wormhole_data.audit_server_ca(request.user_id,request.id,'reset-v1','account_reset_capsule','released');
    RETURN request.capsule;
END
$capsule$;

CREATE FUNCTION wormhole_api_v1.redeem_account_reset(
    p_offer uuid,p_offer_hash bytea,p_proof bytea,p_device uuid,p_name text,
    p_verifier text,p_kdf text,p_nonce bytea,p_ciphertext bytea)
RETURNS TABLE(device_id uuid,wrap_revision bigint,auth_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC'
AS $redeem$
DECLARE request wormhole_data.account_reset_offers; parsed record; device record; role record; target text;
        signed_policy jsonb; next_revision bigint; next_epoch bigint; minimum_kdf integer; selected_kdf integer;
        presets text[]:=ARRAY['kdf-low','kdf-v1','kdf-v2','kdf-v3'];
BEGIN
    IF NOT COALESCE(wormhole_api_v1.account_reset_publication_ready(),false) THEN
        RAISE EXCEPTION 'Account reset redemption logging is enabled' USING ERRCODE='WH024';
    END IF;
    request:=wormhole_data.require_account_reset(p_offer,p_offer_hash,true);
    IF octet_length(p_proof) IS DISTINCT FROM 32 OR pg_catalog.sha256(p_proof) IS DISTINCT FROM request.commit_hash THEN
        RAISE EXCEPTION 'Account reset proof invalid' USING ERRCODE='WH023';
    END IF;
    IF p_device IS NULL OR p_device='00000000-0000-0000-0000-000000000000'::uuid OR
       p_name IS NULL OR octet_length(p_name) NOT BETWEEN 1 AND 4096 OR
       octet_length(p_nonce) IS DISTINCT FROM 12 OR octet_length(p_ciphertext) IS DISTINCT FROM 81 THEN
        RAISE EXCEPTION 'Invalid account reset payload' USING ERRCODE='WH008';
    END IF;
    SELECT pg_catalog.convert_from(m.signed_profile,'UTF8')::jsonb->'policy' INTO STRICT signed_policy
        FROM wormhole_data.workspace_meta m WHERE m.singleton;
    minimum_kdf:=pg_catalog.array_position(presets,signed_policy->>'kdf');
    selected_kdf:=pg_catalog.array_position(presets,p_kdf);
    IF minimum_kdf IS NULL OR selected_kdf IS NULL OR selected_kdf<minimum_kdf OR
       pg_catalog.array_position(presets,request.subject->>'minimumKdf') IS NULL OR
       selected_kdf<pg_catalog.array_position(presets,request.subject->>'minimumKdf') OR
       (p_kdf='kdf-low' AND (signed_policy->>'profile' IS DISTINCT FROM 'default' OR
           signed_policy->>'lowKdfApproved' IS DISTINCT FROM 'true')) THEN
        RAISE EXCEPTION 'Account reset KDF was rejected' USING ERRCODE='WH008';
    END IF;
    SELECT * INTO STRICT parsed FROM wormhole_data.parse_scram_verifier(p_verifier);
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=request.user_id FOR UPDATE NOWAIT;
    PERFORM 1 FROM wormhole_data.devices d WHERE d.user_id=request.user_id ORDER BY d.id FOR UPDATE NOWAIT;
    SELECT a.auth_epoch INTO next_epoch FROM wormhole_data.account_auth a WHERE a.user_id=request.user_id FOR UPDATE NOWAIT;
    IF next_epoch=9223372036854775807 THEN RAISE EXCEPTION 'Account revision exhausted' USING ERRCODE='WH010'; END IF;
    next_epoch:=COALESCE(next_epoch,0)+1;
    next_revision:=(request.subject->>'wrapRevision')::bigint+1;
    target:='wh_{{TAG}}_d_'||p_device::text;
    BEGIN
        FOR device IN SELECT d.* FROM wormhole_data.devices d WHERE d.user_id=request.user_id AND d.status<>'revoked' ORDER BY d.id LOOP
            SELECT r.* INTO role FROM pg_catalog.pg_roles r WHERE r.rolname=device.role_name;
            IF NOT FOUND THEN
                IF device.status='pending' THEN CONTINUE; END IF;
                RAISE EXCEPTION 'Device role unavailable';
            END IF;
            IF role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls
               OR NOT pg_catalog.pg_has_role(role.oid,'wh_{{TAG}}_user','MEMBER')
               OR EXISTS(SELECT FROM wormhole_data.device_confirmations c WHERE c.device_id=device.id AND c.role_oid<>role.oid) THEN
                RAISE EXCEPTION 'Invalid device role';
            END IF;
            EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN PASSWORD NULL',device.role_name);
        END LOOP;
        EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L VALID UNTIL %L',
            target,p_verifier,pg_catalog.clock_timestamp()+interval '1 hour');
        EXECUTE pg_catalog.format('GRANT wh_{{TAG}}_user TO %I WITH INHERIT TRUE, SET FALSE',target);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Reset device credentials could not be installed' USING ERRCODE='WH009';
    END;
    UPDATE wormhole_data.devices d SET status='revoked',row_version=d.row_version+1
        WHERE d.user_id=request.user_id AND d.status<>'revoked';
    DELETE FROM wormhole_data.session_challenges c USING wormhole_data.devices d WHERE c.device_id=d.id AND d.user_id=request.user_id;
    DELETE FROM wormhole_data.device_admissions a USING wormhole_data.devices d WHERE a.device_id=d.id AND d.user_id=request.user_id;
    INSERT INTO wormhole_data.devices(id,user_id,role_name,name,status)
        VALUES(p_device,request.user_id,target,p_name,'active');
    INSERT INTO wormhole_data.account_auth(user_id,auth_epoch,iterations,salt,stored_key,server_key)
        VALUES(request.user_id,next_epoch,parsed.iterations,parsed.salt,parsed.stored_key,parsed.server_key)
    ON CONFLICT(user_id) DO UPDATE SET auth_epoch=EXCLUDED.auth_epoch,iterations=EXCLUDED.iterations,
        salt=EXCLUDED.salt,stored_key=EXCLUDED.stored_key,server_key=EXCLUDED.server_key;
    UPDATE wormhole_data.user_key_wraps w SET wrap_revision=next_revision,kdf_preset=p_kdf,ask_required=true,
        nonce=p_nonce,ciphertext=p_ciphertext WHERE w.user_id=request.user_id;
    UPDATE wormhole_data.users u SET row_version=u.row_version+1 WHERE u.id=request.user_id;
    PERFORM wormhole_data.retire_account_reset(request.id);
    INSERT INTO wormhole_data.account_reset_receipts(offer_id,device_id,wrap_revision,auth_epoch)
        VALUES(request.id,p_device,next_revision,next_epoch);
    BEGIN
        PERFORM wormhole_data.audit_server_ca(request.user_id,request.id,'reset-v1','redeem_account_reset','success');
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    RETURN QUERY SELECT p_device,next_revision,next_epoch;
END
$redeem$;

CREATE FUNCTION wormhole_api_v1.account_reset_receipt(p_capability bytea,p_offer uuid,p_offer_hash bytea)
RETURNS TABLE(wrap_revision bigint,auth_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $receipt$
DECLARE identity record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    RETURN QUERY SELECT r.wrap_revision,r.auth_epoch FROM wormhole_data.account_reset_receipts r
    JOIN wormhole_data.account_reset_offers o ON o.id=r.offer_id
    JOIN wormhole_data.user_key_wraps w ON w.user_id=o.user_id
    JOIN wormhole_data.account_auth a ON a.user_id=o.user_id
    WHERE o.id=p_offer AND o.offer_hash=p_offer_hash AND o.user_id=identity.user_id AND r.device_id=identity.device_id
      AND w.wrap_revision=r.wrap_revision AND a.auth_epoch=r.auth_epoch AND o.retired_at IS NOT NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account reset receipt is unavailable' USING ERRCODE='WH023'; END IF;
END
$receipt$;

REVOKE ALL ON FUNCTION wormhole_data.require_account_reset(uuid,bytea,boolean)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.redeem_account_reset(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea),
    wormhole_api_v1.account_reset_receipt(bytea,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.redeem_account_reset(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea)
    TO wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reset_publication_ready() TO wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reset_receipt(bytea,uuid,bytea) TO wh_{{TAG}}_user;
{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=53 WHERE singleton;
COMMIT;
