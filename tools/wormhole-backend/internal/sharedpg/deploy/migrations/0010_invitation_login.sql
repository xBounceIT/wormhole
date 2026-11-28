-- Version 10: temporary SCRAM roles for invitation bootstrap only.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
SET LOCAL timezone = 'UTC';
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
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 9 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

SET LOCAL ROLE NONE;
CREATE ROLE wh_{{TAG}}_enroll NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT wh_{{TAG}}_enroll TO wh_{{TAG}}_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
DO $connect$
BEGIN
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO wh_{{TAG}}_enroll',pg_catalog.current_database());
END
$connect$;
GRANT USAGE ON SCHEMA wormhole_api_v1 TO wh_{{TAG}}_enroll;
SET LOCAL ROLE wh_{{TAG}}_owner;

CREATE TABLE wormhole_data.invitation_logins (
    invite_id uuid PRIMARY KEY REFERENCES wormhole_data.invites(id),
    role_name name NOT NULL UNIQUE CHECK(role_name::text='wh_{{TAG}}_i_'||invite_id::text),
    role_oid oid NOT NULL UNIQUE,
    revoked boolean NOT NULL DEFAULT false
);

-- Private provisioning primitive: called by the deployer/owner or a future
-- audited invitation-creation API, never granted to enrollment/device roles.
CREATE FUNCTION wormhole_data.provision_invitation_login(p_invite uuid,p_verifier text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $provision$
DECLARE invitation record; target text; created_oid oid;
BEGIN
    SELECT * INTO invitation FROM wormhole_data.invites WHERE id=p_invite FOR UPDATE NOWAIT;
    IF NOT FOUND OR invitation.used_at IS NOT NULL OR invitation.expires_at<=pg_catalog.clock_timestamp() OR invitation.attempts>=5 THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    PERFORM 1 FROM wormhole_data.users WHERE id=invitation.user_id AND NOT disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    PERFORM * FROM wormhole_data.parse_scram_verifier(p_verifier);
    target:='wh_{{TAG}}_i_'||p_invite::text;
    -- CREATE deliberately rejects collisions; never adopt an existing role.
    EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L VALID UNTIL %L',target,p_verifier,invitation.expires_at);
    EXECUTE pg_catalog.format('GRANT wh_{{TAG}}_enroll TO %I WITH INHERIT TRUE, SET FALSE',target);
    SELECT oid INTO STRICT created_oid FROM pg_catalog.pg_roles WHERE rolname=target;
    INSERT INTO wormhole_data.invitation_logins(invite_id,role_name,role_oid) VALUES(p_invite,target,created_oid);
    RETURN target;
END
$provision$;

CREATE FUNCTION wormhole_data.revoke_invitation_login(p_invite uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $revoke$
DECLARE login record;
BEGIN
    SELECT * INTO login FROM wormhole_data.invitation_logins WHERE invite_id=p_invite FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RETURN; END IF;
    -- Name reuse must never let this helper alter an unrelated role.
    PERFORM 1 FROM pg_catalog.pg_roles WHERE oid=login.role_oid AND rolname=login.role_name;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN',login.role_name);
    UPDATE wormhole_data.invitation_logins SET revoked=true WHERE invite_id=p_invite;
END
$revoke$;

CREATE FUNCTION wormhole_data.retire_used_invitation_login() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $retire$
BEGIN
    IF NEW.used_at IS NOT NULL THEN PERFORM wormhole_data.revoke_invitation_login(NEW.id); END IF;
    RETURN NEW;
END
$retire$;
CREATE TRIGGER invites_retire_login AFTER UPDATE OF used_at ON wormhole_data.invites
FOR EACH ROW EXECUTE FUNCTION wormhole_data.retire_used_invitation_login();

CREATE FUNCTION wormhole_api_v1.enrollment_bootstrap(p_invite uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,login_name text,invite_id uuid,bootstrap_key_id uuid,
    bootstrap_key_version integer,expires_at bigint,bootstrap_envelope bytea,manifest bytea,manifest_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $bootstrap$
DECLARE login record; invitation record; account record; meta record;
BEGIN
    -- session_user survives SET ROLE and cannot be replaced by caller input.
    -- Invite then login lock order agrees with consumption/revocation trigger.
    SELECT * INTO invitation FROM wormhole_data.invites WHERE id=p_invite FOR SHARE NOWAIT;
    IF NOT FOUND OR invitation.used_at IS NOT NULL OR invitation.expires_at<=pg_catalog.clock_timestamp() OR invitation.attempts>=5 THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    SELECT * INTO login FROM wormhole_data.invitation_logins l WHERE l.invite_id=p_invite AND l.role_name=session_user AND NOT l.revoked FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    PERFORM 1 FROM pg_catalog.pg_roles r WHERE r.oid=login.role_oid AND r.rolname=login.role_name AND r.rolcanlogin
        AND r.rolvaliduntil IS NOT NULL AND pg_catalog.isfinite(r.rolvaliduntil) AND r.rolvaliduntil>pg_catalog.clock_timestamp()
        AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    SELECT * INTO account FROM wormhole_data.users u WHERE u.id=invitation.user_id AND NOT u.disabled FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.min_api>1 OR meta.max_api<1 THEN RAISE EXCEPTION 'Unsupported API version' USING ERRCODE='WH004'; END IF;
    IF meta.require_tls AND NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) THEN
        RAISE EXCEPTION 'Workspace requires TLS' USING ERRCODE='WH003';
    END IF;
    RETURN QUERY SELECT meta.workspace_id,invitation.user_id,account.login_name,invitation.id,
        invitation.bootstrap_enc_key_id,invitation.bootstrap_enc_key_version,
        pg_catalog.floor(EXTRACT(epoch FROM invitation.expires_at))::bigint,
        invitation.bootstrap_envelope,invitation.manifest,invitation.manifest_revision;
END
$bootstrap$;

REVOKE ALL ON TABLE wormhole_data.invitation_logins FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_data.provision_invitation_login(uuid,text),wormhole_data.revoke_invitation_login(uuid),
    wormhole_data.retire_used_invitation_login(),wormhole_api_v1.enrollment_bootstrap(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.enrollment_bootstrap(uuid) TO wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=10 WHERE singleton;
COMMIT;
