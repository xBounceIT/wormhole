-- Version 8: signed current account key state.
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
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 7 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.user_key_states (
    user_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id),
    state_sequence bigint NOT NULL CHECK(state_sequence>=1),
    signed_state bytea NOT NULL CHECK(pg_catalog.octet_length(signed_state) BETWEEN 1 AND 4096)
);

CREATE FUNCTION wormhole_api_v1.account_key_state(p_capability bytea)
RETURNS TABLE(state_sequence bigint,signed_state bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $state$
DECLARE identity record; current_state record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO current_state FROM wormhole_data.user_key_states s WHERE s.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    RETURN QUERY SELECT current_state.state_sequence,current_state.signed_state;
END
$state$;

CREATE FUNCTION wormhole_api_v1.account_unlock_material(p_capability bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,encryption_key_id uuid,encryption_key_version integer,
    signing_key_id uuid,signing_key_version integer,wrap_revision bigint,kdf_preset text,
    ask_required boolean,nonce bytea,ciphertext bytea,auth_epoch bigint,
    enc_suite smallint,enc_public bytea,enc_signer_id uuid,enc_signer_version integer,enc_cert_revision bigint,enc_signature bytea,
    sign_suite smallint,sign_public bytea,sign_signer_id uuid,sign_signer_version integer,sign_cert_revision bigint,sign_signature bytea,
    signed_state bytea,state_sequence bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $unlock$
DECLARE current_state record;
BEGIN
    SELECT * INTO STRICT current_state FROM wormhole_api_v1.account_key_state(p_capability);
    RETURN QUERY SELECT m.*,current_state.signed_state,current_state.state_sequence
        FROM wormhole_api_v1.account_key_material(p_capability) m;
END
$unlock$;

REVOKE ALL ON wormhole_data.user_key_states FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_key_state(bytea),wormhole_api_v1.account_unlock_material(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_key_state(bytea),wormhole_api_v1.account_unlock_material(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=8 WHERE singleton;
COMMIT;
