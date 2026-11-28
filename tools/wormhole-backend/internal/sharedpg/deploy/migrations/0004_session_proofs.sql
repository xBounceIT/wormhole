-- Version 4: current-credential proof, private challenge state and admission gate.
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
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 3 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE = '55000';
    END IF;
END
$guard$;

-- Keep monitoring authority behind a fixed, own-connection-only helper.
SET LOCAL ROLE NONE;
GRANT CREATE ON SCHEMA wormhole_data TO wh_{{TAG}}_observer;
CREATE FUNCTION wormhole_data.current_backend_start() RETURNS timestamptz
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $start$
    SELECT a.backend_start FROM pg_catalog.pg_stat_activity a
    WHERE a.pid=pg_catalog.pg_backend_pid()
$start$;
ALTER FUNCTION wormhole_data.current_backend_start() OWNER TO wh_{{TAG}}_observer;
REVOKE CREATE ON SCHEMA wormhole_data FROM wh_{{TAG}}_observer;
REVOKE ALL ON FUNCTION wormhole_data.current_backend_start() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_data.current_backend_start() TO wh_{{TAG}}_owner;
SET LOCAL ROLE wh_{{TAG}}_owner;

CREATE TABLE wormhole_data.account_auth (
    user_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id),
    auth_epoch bigint NOT NULL DEFAULT 1 CHECK (auth_epoch >= 1),
    iterations integer NOT NULL CHECK (iterations BETWEEN 4096 AND 1000000),
    salt bytea NOT NULL CHECK (pg_catalog.octet_length(salt) BETWEEN 16 AND 64),
    stored_key bytea NOT NULL CHECK (pg_catalog.octet_length(stored_key)=32),
    server_key bytea NOT NULL CHECK (pg_catalog.octet_length(server_key)=32)
);
CREATE TABLE wormhole_data.session_challenges (
    device_id uuid PRIMARY KEY REFERENCES wormhole_data.devices(id) ON DELETE CASCADE,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 1),
    backend_pid integer NOT NULL CHECK (backend_pid > 0),
    backend_start timestamptz NOT NULL CHECK (pg_catalog.isfinite(backend_start)),
    expires_at bigint NOT NULL CHECK (expires_at > 0),
    client_nonce bytea NOT NULL CHECK (pg_catalog.octet_length(client_nonce)=32),
    server_nonce bytea NOT NULL CHECK (pg_catalog.octet_length(server_nonce)=32),
    capability_hash bytea NOT NULL CHECK (pg_catalog.octet_length(capability_hash)=32
        AND capability_hash <> pg_catalog.decode(pg_catalog.repeat('00',32),'hex'))
);
CREATE TABLE wormhole_data.device_admissions (
    device_id uuid PRIMARY KEY REFERENCES wormhole_data.devices(id) ON DELETE CASCADE,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 1),
    session_id uuid NULL REFERENCES wormhole_data.sessions(id),
    capability_hash bytea NOT NULL CHECK (pg_catalog.octet_length(capability_hash)=32
        AND capability_hash <> pg_catalog.decode(pg_catalog.repeat('00',32),'hex'))
);

-- Private bounded HMAC for the fixed 32-byte SCRAM StoredKey/ServerKey only.
CREATE FUNCTION wormhole_data.scram_hmac(p_key bytea,p_message bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $hmac$
DECLARE inner_pad bytea := pg_catalog.decode(pg_catalog.repeat('36',64),'hex');
        outer_pad bytea := pg_catalog.decode(pg_catalog.repeat('5c',64),'hex'); i integer;
BEGIN
    IF p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32 OR p_message IS NULL
       OR pg_catalog.octet_length(p_message) > 1024 THEN
        RAISE EXCEPTION 'Invalid credential proof' USING ERRCODE = 'WH007';
    END IF;
    FOR i IN 0..31 LOOP
        inner_pad := pg_catalog.set_byte(inner_pad,i,pg_catalog.get_byte(p_key,i) # 54);
        outer_pad := pg_catalog.set_byte(outer_pad,i,pg_catalog.get_byte(p_key,i) # 92);
    END LOOP;
    RETURN pg_catalog.sha256(outer_pad || pg_catalog.sha256(inner_pad || p_message));
END
$hmac$;

-- Raw identity is permitted only to initiate/prove authentication. All business
-- APIs keep calling require_device, which now enforces the admission record.
CREATE FUNCTION wormhole_data.identify_device()
RETURNS TABLE(user_id uuid,device_id uuid,is_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $identity$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Unsupported workspace transaction isolation' USING ERRCODE='WH006';
    END IF;
    RETURN QUERY SELECT u.id,d.id,u.is_admin FROM wormhole_data.devices d
        JOIN wormhole_data.users u ON u.id=d.user_id
        JOIN pg_catalog.pg_roles r ON r.rolname=d.role_name
        WHERE d.role_name=session_user AND d.status='active' AND NOT u.disabled AND r.rolcanlogin;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace account or device unavailable' USING ERRCODE='WH001';
    END IF;
END
$identity$;
-- Preserve the old function OID but fail closed: an API without an explicit
-- capability must never inherit authorization from a pooled server backend.
CREATE OR REPLACE FUNCTION wormhole_data.require_device()
RETURNS TABLE(user_id uuid,device_id uuid,is_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $legacy$
BEGIN
    RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007';
END
$legacy$;

CREATE FUNCTION wormhole_data.require_session_proof(p_capability bytea)
RETURNS TABLE(user_id uuid,device_id uuid,is_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $require$
DECLARE identity record; account record; admitted record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.identify_device();
    IF p_capability IS NULL OR pg_catalog.octet_length(p_capability) <> 32 THEN
        RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007';
    END IF;
    -- Stable lock order: user, device, account, challenge/admission. Hold these
    -- locks until transaction end so revocation/password changes cannot race use.
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=identity.user_id AND NOT u.disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace account unavailable' USING ERRCODE='WH001'; END IF;
    PERFORM 1 FROM wormhole_data.devices d WHERE d.id=identity.device_id AND d.status='active' FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace device unavailable' USING ERRCODE='WH001'; END IF;
    SELECT * INTO account FROM wormhole_data.account_auth a WHERE a.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007'; END IF;
    SELECT * INTO admitted FROM wormhole_data.device_admissions a WHERE a.device_id=identity.device_id FOR SHARE NOWAIT;
    IF NOT FOUND OR admitted.auth_epoch <> account.auth_epoch
       OR admitted.capability_hash <> pg_catalog.sha256(p_capability) THEN
        RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007';
    END IF;
    RETURN QUERY SELECT identity.user_id,identity.device_id,identity.is_admin;
END
$require$;

-- Business APIs require the audited session, not just a successful proof.
CREATE FUNCTION wormhole_data.require_device(p_capability bytea)
RETURNS TABLE(user_id uuid,device_id uuid,is_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $active$
DECLARE identity record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_session_proof(p_capability);
    IF NOT EXISTS (SELECT 1 FROM wormhole_data.device_admissions a
                   WHERE a.device_id=identity.device_id AND a.session_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Audited session required' USING ERRCODE='WH007';
    END IF;
    RETURN QUERY SELECT identity.user_id,identity.device_id,identity.is_admin;
END
$active$;

CREATE FUNCTION wormhole_api_v1.session_challenge(p_client_nonce bytea,p_capability_hash bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,auth_epoch bigint,backend_pid integer,
              expires_at bigint,server_nonce bytea,salt bytea,iterations integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $challenge$
DECLARE identity record; account record; meta record; start_at timestamptz;
        expiry bigint; nonce bytea;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.identify_device();
    IF p_client_nonce IS NULL OR pg_catalog.octet_length(p_client_nonce) <> 32
       OR p_capability_hash IS NULL OR pg_catalog.octet_length(p_capability_hash) <> 32
       OR p_capability_hash = pg_catalog.decode(pg_catalog.repeat('00',32),'hex') THEN
        RAISE EXCEPTION 'Invalid credential proof' USING ERRCODE='WH007';
    END IF;
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=identity.user_id AND NOT u.disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace account unavailable' USING ERRCODE='WH001'; END IF;
    PERFORM 1 FROM wormhole_data.devices d WHERE d.id=identity.device_id AND d.status='active' FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace device unavailable' USING ERRCODE='WH001'; END IF;
    SELECT * INTO account FROM wormhole_data.account_auth a WHERE a.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007'; END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    IF meta.state <> 'ready' OR meta.signed_profile IS NULL THEN
        RAISE EXCEPTION 'Workspace provisioning is incomplete' USING ERRCODE='WH002';
    END IF;
    IF meta.require_tls AND NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) THEN
        RAISE EXCEPTION 'Workspace requires TLS' USING ERRCODE='WH003';
    END IF;
    start_at := wormhole_data.current_backend_start();
    IF start_at IS NULL THEN RAISE EXCEPTION 'Connection identity unavailable' USING ERRCODE='WH007'; END IF;
    expiry := pg_catalog.floor(EXTRACT(epoch FROM pg_catalog.clock_timestamp()))::bigint + 30;
    nonce := pg_catalog.uuid_send(pg_catalog.gen_random_uuid()) || pg_catalog.uuid_send(pg_catalog.gen_random_uuid());
    INSERT INTO wormhole_data.session_challenges AS c(device_id,auth_epoch,backend_pid,backend_start,expires_at,client_nonce,server_nonce,capability_hash)
    VALUES(identity.device_id,account.auth_epoch,pg_catalog.pg_backend_pid(),start_at,expiry,p_client_nonce,nonce,p_capability_hash)
    ON CONFLICT ON CONSTRAINT session_challenges_pkey DO UPDATE SET
       auth_epoch=EXCLUDED.auth_epoch,backend_pid=EXCLUDED.backend_pid,backend_start=EXCLUDED.backend_start,
       expires_at=EXCLUDED.expires_at,client_nonce=EXCLUDED.client_nonce,server_nonce=EXCLUDED.server_nonce,
       capability_hash=EXCLUDED.capability_hash;
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,account.auth_epoch,
                        pg_catalog.pg_backend_pid(),expiry,nonce,account.salt,account.iterations;
END
$challenge$;

CREATE FUNCTION wormhole_api_v1.session_prove(p_proof bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $prove$
DECLARE identity record; account record; challenge record; workspace uuid; start_at timestamptz;
        server_context bytea; client_nonce text; combined text; message bytea;
        signature bytea; client_key bytea; actual bytea; mismatch integer := 0; i integer;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.identify_device();
    IF p_proof IS NULL OR pg_catalog.octet_length(p_proof) <> 32 THEN
        RAISE EXCEPTION 'Invalid credential proof' USING ERRCODE='WH007';
    END IF;
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=identity.user_id AND NOT u.disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace account unavailable' USING ERRCODE='WH001'; END IF;
    PERFORM 1 FROM wormhole_data.devices d WHERE d.id=identity.device_id AND d.status='active' FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Workspace device unavailable' USING ERRCODE='WH001'; END IF;
    SELECT * INTO account FROM wormhole_data.account_auth a WHERE a.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Current credential proof required' USING ERRCODE='WH007'; END IF;
    SELECT * INTO challenge FROM wormhole_data.session_challenges c WHERE c.device_id=identity.device_id FOR UPDATE NOWAIT;
    start_at := wormhole_data.current_backend_start();
    IF NOT FOUND OR start_at IS NULL OR challenge.backend_start IS DISTINCT FROM start_at
       OR challenge.backend_pid <> pg_catalog.pg_backend_pid() OR challenge.auth_epoch <> account.auth_epoch
       OR challenge.expires_at <= EXTRACT(epoch FROM pg_catalog.clock_timestamp()) THEN
        RAISE EXCEPTION 'Invalid credential proof' USING ERRCODE='WH007';
    END IF;
    SELECT m.workspace_id INTO STRICT workspace FROM wormhole_data.workspace_meta m WHERE singleton;
    server_context := pg_catalog.convert_to('wormhole/v1/session-proof','UTF8') || pg_catalog.uuid_send(workspace)
        || pg_catalog.uuid_send(identity.user_id) || pg_catalog.uuid_send(identity.device_id)
        || pg_catalog.int8send(challenge.auth_epoch) || pg_catalog.int4send(challenge.backend_pid)
        || pg_catalog.int8send(challenge.expires_at) || challenge.server_nonce || challenge.capability_hash;
    client_nonce := pg_catalog.translate(pg_catalog.rtrim(pg_catalog.encode(challenge.client_nonce,'base64'),'='),'+/','-_');
    combined := client_nonce || pg_catalog.translate(pg_catalog.rtrim(pg_catalog.encode(pg_catalog.sha256(server_context),'base64'),'='),'+/','-_');
    message := pg_catalog.convert_to('n=' || identity.device_id::text || ',r=' || client_nonce || ',r=' || combined
        || ',s=' || pg_catalog.replace(pg_catalog.encode(account.salt,'base64'),E'\n','') || ',i=' || account.iterations::text
        || ',c=biws,r=' || combined,'UTF8');
    signature := wormhole_data.scram_hmac(account.stored_key,message);
    client_key := p_proof;
    FOR i IN 0..31 LOOP
        client_key := pg_catalog.set_byte(client_key,i,pg_catalog.get_byte(p_proof,i) # pg_catalog.get_byte(signature,i));
    END LOOP;
    actual := pg_catalog.sha256(client_key);
    -- Examine every byte; PL/pgSQL itself is not a constant-time runtime.
    FOR i IN 0..31 LOOP
        mismatch := mismatch | (pg_catalog.get_byte(actual,i) # pg_catalog.get_byte(account.stored_key,i));
    END LOOP;
    IF mismatch <> 0 THEN RAISE EXCEPTION 'Invalid credential proof' USING ERRCODE='WH007'; END IF;
    DELETE FROM wormhole_data.session_challenges c WHERE c.device_id=identity.device_id;
    INSERT INTO wormhole_data.device_admissions AS a(device_id,auth_epoch,capability_hash)
    VALUES(identity.device_id,account.auth_epoch,challenge.capability_hash)
    ON CONFLICT ON CONSTRAINT device_admissions_pkey DO UPDATE SET
        auth_epoch=EXCLUDED.auth_epoch,capability_hash=EXCLUDED.capability_hash,session_id=NULL;
    RETURN wormhole_data.scram_hmac(account.server_key,message);
END
$prove$;

CREATE FUNCTION wormhole_api_v1.session_start(p_api integer,p_app_version text,p_source text,p_capability bytea)
RETURNS TABLE(session_id uuid,workspace_id uuid,user_id uuid,device_id uuid,is_admin boolean,
              min_api integer,max_api integer,epoch bigint,change_seq bigint,signed_profile bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
SET statement_timeout = '15s'
SET timezone = 'UTC'
AS $admit$
DECLARE identity record; meta record; tls record; admitted uuid;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_session_proof(p_capability);
    PERFORM 1 FROM wormhole_data.device_admissions a WHERE a.device_id=identity.device_id FOR UPDATE NOWAIT;
    IF p_api IS NULL OR p_app_version IS NULL OR pg_catalog.octet_length(p_app_version) NOT BETWEEN 1 AND 64
       OR p_app_version !~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'
       OR p_app_version ~ '[[:cntrl:]]' OR p_source IS NULL OR p_source NOT IN ('ui','mcp') THEN
        RAISE EXCEPTION 'Invalid workspace session request' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    IF meta.state <> 'ready' OR meta.signed_profile IS NULL THEN
        RAISE EXCEPTION 'Workspace provisioning is incomplete' USING ERRCODE = 'WH002';
    END IF;
    IF p_api NOT BETWEEN meta.min_api AND meta.max_api THEN
        RAISE EXCEPTION 'Unsupported workspace API version' USING ERRCODE = 'WH004';
    END IF;
    SELECT * INTO STRICT tls FROM wormhole_data.current_connection_tls();
    IF meta.require_tls AND tls.ssl IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Workspace requires TLS' USING ERRCODE = 'WH003';
    END IF;
    INSERT INTO wormhole_data.sessions(user_id,device_id,session_role,backend_pid,ssl,tls_version,client_dn,client_addr,app_version)
    VALUES(identity.user_id,identity.device_id,session_user,pg_catalog.pg_backend_pid(),
           COALESCE(tls.ssl,false),tls.version,tls.client_dn,pg_catalog.inet_client_addr(),p_app_version)
    RETURNING id INTO admitted;
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
        VALUES(identity.user_id,admitted,session_user,p_source,'login','success',pg_catalog.inet_client_addr(),p_app_version);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE = 'WH005';
    END;
    UPDATE wormhole_data.device_admissions a SET session_id=admitted WHERE a.device_id=identity.device_id;
    RETURN QUERY SELECT admitted,meta.workspace_id,identity.user_id,identity.device_id,identity.is_admin,
                        meta.min_api,meta.max_api,meta.epoch,meta.change_seq,meta.signed_profile;
END
$admit$;
REVOKE ALL ON FUNCTION wormhole_api_v1.session_start(integer,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.session_start(integer,text,text,bytea) TO wh_{{TAG}}_user;

REVOKE ALL ON wormhole_data.account_auth,wormhole_data.session_challenges,wormhole_data.device_admissions FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
REVOKE ALL ON FUNCTION wormhole_data.scram_hmac(bytea,bytea),wormhole_data.identify_device(),wormhole_data.require_device(),wormhole_data.require_device(bytea),wormhole_data.require_session_proof(bytea),
    wormhole_api_v1.session_challenge(bytea,bytea),wormhole_api_v1.session_prove(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.session_challenge(bytea,bytea),wormhole_api_v1.session_prove(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=4 WHERE singleton;
COMMIT;
