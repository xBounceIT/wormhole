-- Version 7: atomic account capsule and certificate retrieval.
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
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 6 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Certificate revision is signed data, independent of mutable row_version/status.
-- Existing keys remain uncertified until explicitly issued a certificate.
ALTER TABLE wormhole_data.keys ADD COLUMN cert_revision bigint CHECK(cert_revision>=1);

CREATE FUNCTION wormhole_api_v1.account_key_material(p_capability bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,encryption_key_id uuid,encryption_key_version integer,
    signing_key_id uuid,signing_key_version integer,wrap_revision bigint,kdf_preset text,
    ask_required boolean,nonce bytea,ciphertext bytea,auth_epoch bigint,
    enc_suite smallint,enc_public bytea,enc_signer_id uuid,enc_signer_version integer,enc_cert_revision bigint,enc_signature bytea,
    sign_suite smallint,sign_public bytea,sign_signer_id uuid,sign_signer_version integer,sign_cert_revision bigint,sign_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $material$
DECLARE wrapped record; enc record; sign record;
BEGIN
    -- Reuse audited identity/epoch validation and retain its user/wrapper locks.
    SELECT * INTO STRICT wrapped FROM wormhole_api_v1.account_keys(p_capability);
    SELECT * INTO STRICT enc FROM wormhole_data.keys k WHERE k.key_id=wrapped.encryption_key_id AND k.key_version=wrapped.encryption_key_version FOR SHARE NOWAIT;
    SELECT * INTO STRICT sign FROM wormhole_data.keys k WHERE k.key_id=wrapped.signing_key_id AND k.key_version=wrapped.signing_key_version FOR SHARE NOWAIT;
    IF enc.kind<>'user-enc' OR sign.kind<>'user-sign' OR enc.owner_id IS DISTINCT FROM wrapped.user_id
       OR sign.owner_id IS DISTINCT FROM wrapped.user_id OR enc.status<>'active' OR sign.status<>'active'
       OR enc.suite<>2 OR sign.suite<>1 OR enc.public_key IS NULL OR sign.public_key IS NULL
       OR pg_catalog.octet_length(enc.public_key)<>32 OR pg_catalog.octet_length(sign.public_key)<>32
       OR enc.cert_revision IS NULL OR sign.cert_revision IS NULL
       OR enc.cert_signature IS NULL OR sign.cert_signature IS NULL
       OR enc.cert_signer_key_id IS DISTINCT FROM sign.cert_signer_key_id
       OR enc.cert_signer_key_version IS DISTINCT FROM sign.cert_signer_key_version
       OR NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=enc.cert_signer_key_id
           AND k.key_version=enc.cert_signer_key_version AND k.kind='org-sign') THEN
        RAISE EXCEPTION 'Account certificates unavailable' USING ERRCODE='WH010';
    END IF;
    RETURN QUERY SELECT wrapped.workspace_id,wrapped.user_id,wrapped.encryption_key_id,wrapped.encryption_key_version,
        wrapped.signing_key_id,wrapped.signing_key_version,wrapped.wrap_revision,wrapped.kdf_preset,
        wrapped.ask_required,wrapped.nonce,wrapped.ciphertext,wrapped.auth_epoch,
        enc.suite,enc.public_key,enc.cert_signer_key_id,enc.cert_signer_key_version,enc.cert_revision,enc.cert_signature,
        sign.suite,sign.public_key,sign.cert_signer_key_id,sign.cert_signer_key_version,sign.cert_revision,sign.cert_signature;
END
$material$;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_key_material(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_key_material(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=7 WHERE singleton;
COMMIT;
