-- Version 5: account key wrappers and atomic self-service password replacement.
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
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 4 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Fixed v1/AES-256-GCM user-key capsule: 65 plaintext bytes + 16-byte tag.
-- No plaintext keys or ASK are stored here. The password-change API preserves
-- key references, KDF preset and ASK requirement; reset/enrollment are separate.
CREATE TABLE wormhole_data.user_key_wraps (
    user_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id),
    encryption_key_id uuid NOT NULL,
    encryption_key_version integer NOT NULL,
    signing_key_id uuid NOT NULL,
    signing_key_version integer NOT NULL,
    wrap_revision bigint NOT NULL DEFAULT 1 CHECK (wrap_revision >= 1),
    kdf_preset text NOT NULL CHECK (kdf_preset IN ('kdf-low','kdf-v1','kdf-v2','kdf-v3')),
    ask_required boolean NOT NULL,
    nonce bytea NOT NULL CHECK (pg_catalog.octet_length(nonce)=12),
    ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(ciphertext)=81),
    FOREIGN KEY(encryption_key_id,encryption_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    FOREIGN KEY(signing_key_id,signing_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK (encryption_key_id <> signing_key_id)
);

CREATE FUNCTION wormhole_data.parse_scram_verifier(p_verifier text)
RETURNS TABLE(iterations integer,salt bytea,stored_key bytea,server_key bytea)
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $parse$
DECLARE parts text[]; cost integer; decoded_salt bytea; decoded_stored bytea; decoded_server bytea; canonical text;
BEGIN
    IF p_verifier IS NULL OR pg_catalog.octet_length(p_verifier)>256 THEN
        RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008';
    END IF;
    parts := pg_catalog.regexp_match(p_verifier,'^SCRAM-SHA-256[$]([1-9][0-9]{3,6}):([A-Za-z0-9+/=]+)[$]([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$');
    IF parts IS NULL THEN RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008'; END IF;
    cost := parts[1]::integer;
    BEGIN
        decoded_salt := pg_catalog.decode(parts[2],'base64');
        decoded_stored := pg_catalog.decode(parts[3],'base64');
        decoded_server := pg_catalog.decode(parts[4],'base64');
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008';
    END;
    IF cost NOT BETWEEN 4096 AND 1000000 OR pg_catalog.octet_length(decoded_salt) NOT BETWEEN 16 AND 64
       OR pg_catalog.octet_length(decoded_stored)<>32 OR pg_catalog.octet_length(decoded_server)<>32 THEN
        RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008';
    END IF;
    canonical := 'SCRAM-SHA-256$' || cost::text || ':' || pg_catalog.replace(pg_catalog.encode(decoded_salt,'base64'),E'\n','')
        || '$' || pg_catalog.encode(decoded_stored,'base64') || ':' || pg_catalog.encode(decoded_server,'base64');
    IF p_verifier <> canonical THEN RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008'; END IF;
    RETURN QUERY SELECT cost,decoded_salt,decoded_stored,decoded_server;
END
$parse$;

CREATE FUNCTION wormhole_api_v1.change_password(p_capability bytea,p_expected_revision bigint,
    p_verifier text,p_nonce bytea,p_ciphertext bytea,p_source text DEFAULT 'ui')
RETURNS TABLE(wrap_revision bigint,auth_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $change$
DECLARE identity record; account record; wrapped record; parsed record; device record; role record;
        session_record record; next_epoch bigint; next_revision bigint;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_expected_revision IS NULL OR p_expected_revision<1 OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce)<>12
       OR p_ciphertext IS NULL OR pg_catalog.octet_length(p_ciphertext)<>81 OR p_source IS NULL OR p_source NOT IN ('ui','mcp') THEN
        RAISE EXCEPTION 'Invalid password change payload' USING ERRCODE='WH008';
    END IF;
    SELECT * INTO STRICT parsed FROM wormhole_data.parse_scram_verifier(p_verifier);
    -- Upgrade the account lock first, then lock every device deterministically.
    -- Existing API readers hold the user lock, so the operation refuses busy use.
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=identity.user_id FOR UPDATE NOWAIT;
    PERFORM 1 FROM wormhole_data.devices d WHERE d.user_id=identity.user_id ORDER BY d.id FOR UPDATE NOWAIT;
    SELECT * INTO STRICT account FROM wormhole_data.account_auth a WHERE a.user_id=identity.user_id FOR UPDATE NOWAIT;
    SELECT * INTO wrapped FROM wormhole_data.user_key_wraps w WHERE w.user_id=identity.user_id FOR UPDATE NOWAIT;
    IF NOT FOUND OR wrapped.wrap_revision<>p_expected_revision THEN
        RAISE EXCEPTION 'Account wrapping revision changed' USING ERRCODE='WH010';
    END IF;
    IF account.auth_epoch=9223372036854775807 OR wrapped.wrap_revision=9223372036854775807 THEN
        RAISE EXCEPTION 'Account revision exhausted' USING ERRCODE='WH010';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=wrapped.encryption_key_id
          AND k.key_version=wrapped.encryption_key_version AND k.kind='user-enc' AND k.owner_id=identity.user_id AND k.status='active')
       OR NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=wrapped.signing_key_id
          AND k.key_version=wrapped.signing_key_version AND k.kind='user-sign' AND k.owner_id=identity.user_id AND k.status='active') THEN
        RAISE EXCEPTION 'Account key metadata unavailable' USING ERRCODE='WH008';
    END IF;
    SELECT s.* INTO STRICT session_record FROM wormhole_data.sessions s JOIN wormhole_data.device_admissions a ON a.session_id=s.id
        WHERE a.device_id=identity.device_id;
    next_epoch := account.auth_epoch+1;
    next_revision := wrapped.wrap_revision+1;
    -- Owner-created device roles carry ADMIN OPTION in PostgreSQL 16+. Never
    -- enable LOGIN, renew expiry or change privileges while replacing a verifier.
    BEGIN
        FOR device IN SELECT d.* FROM wormhole_data.devices d WHERE d.user_id=identity.user_id ORDER BY d.id LOOP
            SELECT r.* INTO role FROM pg_catalog.pg_roles r WHERE r.rolname=device.role_name;
            IF NOT FOUND THEN
                IF device.status='pending' THEN CONTINUE; END IF;
                RAISE EXCEPTION 'Device role unavailable';
            END IF;
            IF role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls THEN
                RAISE EXCEPTION 'Invalid device role';
            END IF;
            EXECUTE pg_catalog.format('ALTER ROLE %I PASSWORD %L',device.role_name,p_verifier);
        END LOOP;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Device credentials could not be updated' USING ERRCODE='WH009';
    END;
    UPDATE wormhole_data.account_auth a SET iterations=parsed.iterations,salt=parsed.salt,stored_key=parsed.stored_key,
        server_key=parsed.server_key,auth_epoch=next_epoch WHERE a.user_id=identity.user_id;
    UPDATE wormhole_data.user_key_wraps w SET nonce=p_nonce,ciphertext=p_ciphertext,wrap_revision=next_revision WHERE w.user_id=identity.user_id;
    UPDATE wormhole_data.users u SET row_version=u.row_version+1 WHERE u.id=identity.user_id;
    DELETE FROM wormhole_data.session_challenges c USING wormhole_data.devices d WHERE c.device_id=d.id AND d.user_id=identity.user_id;
    DELETE FROM wormhole_data.device_admissions a USING wormhole_data.devices d WHERE a.device_id=d.id AND d.user_id=identity.user_id;
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
        VALUES(identity.user_id,session_record.id,session_user,p_source,'change_password','success',pg_catalog.inet_client_addr(),session_record.app_version);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005';
    END;
    RETURN QUERY SELECT next_revision,next_epoch;
END
$change$;

REVOKE ALL ON wormhole_data.user_key_wraps FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
REVOKE ALL ON FUNCTION wormhole_data.parse_scram_verifier(text),wormhole_api_v1.change_password(bytea,bigint,text,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.change_password(bytea,bigint,text,bytea,bytea,text) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=5 WHERE singleton;
COMMIT;
