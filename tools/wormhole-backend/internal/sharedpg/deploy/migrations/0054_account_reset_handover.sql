-- Version 54: custodian reset queue and durable per-offer handover.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>53 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.account_reset_offers
    ADD COLUMN handed_over_at timestamptz CHECK(pg_catalog.isfinite(handed_over_at) AND handed_over_at<=expires_at),
    ADD COLUMN handed_over_by uuid REFERENCES wormhole_data.users(id),
    ADD CONSTRAINT account_reset_handover_complete CHECK((handed_over_at IS NULL)=(handed_over_by IS NULL));
CREATE INDEX account_reset_offers_user_history ON wormhole_data.account_reset_offers
    (user_id,(retired_at IS NULL) DESC,expires_at DESC,retired_at DESC NULLS FIRST,id DESC);

CREATE FUNCTION wormhole_api_v1.account_reset_targets(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,
    p_after uuid,p_limit integer)
RETURNS TABLE(user_id uuid,login_name text,eligible boolean,offer_id uuid,status text,expires_at bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $targets$
DECLARE actor record;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'Invalid reset page size' USING ERRCODE='WH023';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR NOT actor.custodian OR actor.recipient_signature IS NULL THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    RETURN QUERY
    WITH page AS MATERIALIZED (
        SELECT u.id,u.login_name,e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version,
            w.wrap_revision,pg_catalog.sha256(e.certificate) AS cert_hash,pg_catalog.sha256(s.signed_state) AS state_hash
        FROM wormhole_data.users u
        JOIN wormhole_data.user_enrollments e ON e.user_id=u.id
        JOIN wormhole_data.user_key_wraps w ON w.user_id=u.id
        JOIN wormhole_data.user_key_states s ON s.user_id=u.id
        WHERE NOT u.disabled AND (p_after IS NULL OR u.id>p_after)
          AND pg_catalog.convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true'
          AND (w.encryption_key_id,w.encryption_key_version)=(e.encryption_key_id,e.encryption_key_version)
          AND (w.signing_key_id,w.signing_key_version)=(e.signing_key_id,e.signing_key_version)
        ORDER BY u.id LIMIT p_limit
    )
    SELECT a.id,a.login_name,a.wrap_revision<9223372036854775807 AND (
        SELECT count(*)=2 FROM wormhole_data.key_copies c
        WHERE (c.key_id,c.key_version) IN ((a.encryption_key_id,a.encryption_key_version),(a.signing_key_id,a.signing_key_version))
          AND (c.holder_key_id,c.holder_key_version)=(actor.recipient_id,actor.recipient_version)
          AND (c.issuer_key_id,c.issuer_key_version)=(a.signing_key_id,a.signing_key_version)
          AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
    ),o.id,
    CASE
        WHEN o.id IS NULL THEN 'not-issued'
        WHEN r.offer_id IS NOT NULL THEN 'redeemed'
        WHEN o.retired_at IS NOT NULL THEN 'inactive'
        WHEN o.expires_at<=pg_catalog.statement_timestamp() THEN 'expired'
        WHEN o.tls_hash IS DISTINCT FROM p_tls_digest OR o.policy_hash IS DISTINCT FROM p_policy_digest
          OR o.subject->>'wrapRevision' IS DISTINCT FROM a.wrap_revision::text
          OR o.subject->>'certificateDigest' IS DISTINCT FROM pg_catalog.encode(a.cert_hash,'base64')
          OR o.subject->>'stateDigest' IS DISTINCT FROM pg_catalog.encode(a.state_hash,'base64')
          OR NOT EXISTS(SELECT FROM pg_catalog.pg_roles roles WHERE roles.oid=o.role_oid AND roles.rolname=o.role_name AND roles.rolcanlogin)
        THEN 'inactive'
        WHEN o.handed_over_at IS NOT NULL THEN 'handed-over'
        ELSE 'awaiting-handover'
    END,
    floor(EXTRACT(epoch FROM o.expires_at))::bigint
    FROM page a
    LEFT JOIN LATERAL (
        SELECT offers.id,offers.retired_at,offers.expires_at,offers.tls_hash,offers.policy_hash,
            offers.subject,offers.role_oid,offers.role_name,offers.handed_over_at
        FROM wormhole_data.account_reset_offers offers WHERE offers.user_id=a.id
        ORDER BY (offers.retired_at IS NULL) DESC,offers.expires_at DESC,offers.retired_at DESC NULLS FIRST,offers.id DESC
        LIMIT 1
    ) o ON true
    LEFT JOIN wormhole_data.account_reset_receipts r ON r.offer_id=o.id
    ORDER BY a.id;
END
$targets$;

CREATE FUNCTION wormhole_api_v1.mark_account_reset_handover(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,
    p_user uuid,p_offer uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $handover$
DECLARE actor record; offer wormhole_data.account_reset_offers; marked_at timestamptz;
BEGIN
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND OR NOT actor.custodian OR actor.recipient_signature IS NULL THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    SELECT * INTO offer FROM wormhole_data.account_reset_offers o WHERE o.id=p_offer AND o.user_id=p_user FOR UPDATE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    IF EXISTS(SELECT FROM wormhole_data.account_reset_receipts r WHERE r.offer_id=p_offer) THEN
        RETURN 'redeemed';
    END IF;
    marked_at:=pg_catalog.clock_timestamp();
    IF offer.retired_at IS NOT NULL OR offer.expires_at<=marked_at
       OR offer.tls_hash IS DISTINCT FROM p_tls_digest OR offer.policy_hash IS DISTINCT FROM p_policy_digest
       OR offer.subject IS DISTINCT FROM wormhole_data.account_reset_target(offer.subject->>'loginName')
       OR NOT EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=offer.role_oid AND r.rolname=offer.role_name AND r.rolcanlogin) THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    IF offer.handed_over_at IS NULL THEN
        UPDATE wormhole_data.account_reset_offers SET handed_over_at=marked_at,handed_over_by=actor.actor WHERE id=p_offer;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'mark_account_reset_handover','handed_over');
    END IF;
    RETURN 'handed-over';
END
$handover$;

REVOKE ALL ON FUNCTION wormhole_api_v1.account_reset_targets(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer),
    wormhole_api_v1.mark_account_reset_handover(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid)
    FROM PUBLIC,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
-- Device logins use the common user role. Custodianship is rechecked against
-- the active device capability and certified organisation custody in each API.
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reset_targets(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer),
    wormhole_api_v1.mark_account_reset_handover(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid) TO wh_{{TAG}}_user;
{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=54 WHERE singleton;
COMMIT;
