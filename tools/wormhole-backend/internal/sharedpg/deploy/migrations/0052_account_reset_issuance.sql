-- Version 52: audited account reset offers and enrollment-only SCRAM access.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>51 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- The reset role inherits the enrollment group. It cannot use the ordinary
-- invitation APIs because it owns no invitation_logins entry.
CREATE TABLE wormhole_data.account_reset_offers (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    issuer_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    role_oid oid NOT NULL UNIQUE,
    role_name name NOT NULL UNIQUE CHECK(role_name::text='wh_{{TAG}}_r_'||id::text),
    expires_at timestamptz NOT NULL CHECK(pg_catalog.isfinite(expires_at)),
    subject jsonb NOT NULL,
    offer_hash bytea NOT NULL CHECK(pg_catalog.octet_length(offer_hash)=32),
    commit_hash bytea NOT NULL CHECK(pg_catalog.octet_length(commit_hash)=32),
    policy_hash bytea NOT NULL CHECK(pg_catalog.octet_length(policy_hash)=32),
    tls_hash bytea NOT NULL CHECK(pg_catalog.octet_length(tls_hash)=32),
    capsule bytea CHECK(pg_catalog.octet_length(capsule) BETWEEN 16 AND 512),
    retired_at timestamptz CHECK(pg_catalog.isfinite(retired_at)),
    CHECK((retired_at IS NULL)=(capsule IS NOT NULL))
);
CREATE UNIQUE INDEX account_reset_offers_pending ON wormhole_data.account_reset_offers(user_id) WHERE retired_at IS NULL;
REVOKE ALL ON TABLE wormhole_data.account_reset_offers
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

CREATE FUNCTION wormhole_data.account_reset_target(p_login text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $target$
DECLARE target record;
BEGIN
    SELECT u.id,u.login_name,e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version,
           w.wrap_revision,w.kdf_preset,e.certificate,s.signed_state
    INTO target
    FROM wormhole_data.users u
    JOIN wormhole_data.user_enrollments e ON e.user_id=u.id
    JOIN wormhole_data.user_key_wraps w ON w.user_id=u.id
    JOIN wormhole_data.user_key_states s ON s.user_id=u.id
    WHERE u.login_name=p_login AND NOT u.disabled
      AND pg_catalog.convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true'
      AND (w.encryption_key_id,w.encryption_key_version)=(e.encryption_key_id,e.encryption_key_version)
      AND (w.signing_key_id,w.signing_key_version)=(e.signing_key_id,e.signing_key_version)
      AND w.wrap_revision<9223372036854775807
    FOR SHARE OF u,e,w,s NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023'; END IF;
    RETURN pg_catalog.jsonb_build_object('userId',target.id,'loginName',target.login_name,
        'encryption',pg_catalog.jsonb_build_object('id',target.encryption_key_id,'version',target.encryption_key_version),
        'signing',pg_catalog.jsonb_build_object('id',target.signing_key_id,'version',target.signing_key_version),
        'wrapRevision',target.wrap_revision,'minimumKdf',target.kdf_preset,
        'certificateDigest',pg_catalog.encode(pg_catalog.sha256(target.certificate),'base64'),
        'stateDigest',pg_catalog.encode(pg_catalog.sha256(target.signed_state),'base64'));
END
$target$;

CREATE FUNCTION wormhole_data.retire_account_reset(p_offer uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $retire$
DECLARE old wormhole_data.account_reset_offers;
BEGIN
    SELECT * INTO STRICT old FROM wormhole_data.account_reset_offers WHERE id=p_offer AND retired_at IS NULL FOR UPDATE NOWAIT;
    IF EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=old.role_oid AND r.rolname=old.role_name) THEN
        EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN PASSWORD NULL',old.role_name);
    END IF;
    UPDATE wormhole_data.account_reset_offers
    SET retired_at=pg_catalog.clock_timestamp(),capsule=NULL WHERE id=p_offer;
END
$retire$;

CREATE FUNCTION wormhole_api_v1.account_reset_material(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,p_login text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE actor record; subject jsonb; target_id uuid; state bytea; certificate bytea; copies jsonb; tag text;
BEGIN
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND OR NOT actor.custodian OR actor.recipient_signature IS NULL
       OR octet_length(p_login) NOT BETWEEN 1 AND 256 OR p_login IS NULL THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    subject:=wormhole_data.account_reset_target(p_login);
    target_id:=(subject->>'userId')::uuid;
    SELECT e.certificate,s.signed_state INTO STRICT certificate,state
      FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_states s USING(user_id)
      WHERE e.user_id=target_id;
    SELECT pg_catalog.jsonb_agg(wire ORDER BY wire->>'id') INTO copies
    FROM (
        SELECT pg_catalog.jsonb_build_object('id',c.key_id,'version',c.key_version,
            'enc',pg_catalog.encode(c.enc,'base64'),'ciphertext',pg_catalog.encode(c.ciphertext,'base64'),
            'signature',pg_catalog.encode(c.signature,'base64')) AS wire
        FROM wormhole_data.key_copies c
        WHERE c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48 AND (
            ((c.key_id,c.key_version) IN ((actor.recipient_id,actor.recipient_version),(actor.organisation_signer,actor.organisation_version))
             AND (c.holder_key_id,c.holder_key_version)=(p_holder,p_holder_version)
             AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version))
            OR
            ((c.key_id,c.key_version) IN (((subject#>>'{encryption,id}')::uuid,(subject#>>'{encryption,version}')::integer),
                                          ((subject#>>'{signing,id}')::uuid,(subject#>>'{signing,version}')::integer))
             AND (c.holder_key_id,c.holder_key_version)=(actor.recipient_id,actor.recipient_version)
             AND (c.issuer_key_id,c.issuer_key_version)=((subject#>>'{signing,id}')::uuid,(subject#>>'{signing,version}')::integer)))
        FOR SHARE NOWAIT
    ) sealed;
    IF pg_catalog.jsonb_array_length(copies) IS DISTINCT FROM 4 THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,
        'account_reset_material','key_copies_released');
    SELECT role_tag INTO STRICT tag FROM wormhole_data.workspace_meta WHERE singleton;
    RETURN pg_catalog.jsonb_build_object('roleTag',tag,'database',pg_catalog.current_database(),
        'subject',subject,'signedState',pg_catalog.encode(state,'base64'),
        'enrollment',pg_catalog.encode(certificate,'base64'),'copies',copies,
        'recipient',pg_catalog.jsonb_build_object('id',actor.recipient_id,'version',actor.recipient_version),
        'recipientPublic',pg_catalog.encode(actor.recipient_public,'base64'),
        'recipientProof',pg_catalog.encode(actor.recipient_signature,'base64'));
END
$material$;

CREATE FUNCTION wormhole_api_v1.account_reset_publication_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $logging$
    SELECT pg_catalog.current_setting('log_statement')='none'
       AND pg_catalog.current_setting('log_parameter_max_length')='0'
       AND pg_catalog.current_setting('log_parameter_max_length_on_error')='0'
       AND COALESCE(pg_catalog.current_setting('pgaudit.log',true),'none')='none'
       AND COALESCE(pg_catalog.current_setting('pgaudit.log_parameter',true),'off')='off'
       AND (COALESCE(pg_catalog.current_setting('pg_stat_statements.track',true),'top')<>'all'
            OR pg_catalog.current_setting('pg_stat_statements.track_utility',true)='off');
$logging$;

CREATE FUNCTION wormhole_api_v1.publish_account_reset(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,
    p_offer uuid,p_subject jsonb,p_expires bigint,p_offer_hash bytea,p_commit_hash bytea,p_capsule bytea,p_verifier text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC'
AS $publish$
DECLARE actor record; subject jsonb; target_id uuid; expiry timestamptz; login text; new_oid oid; previous record;
BEGIN
    IF NOT COALESCE(wormhole_api_v1.account_reset_publication_ready(),false) THEN
        RAISE EXCEPTION 'Account reset publication logging is enabled' USING ERRCODE='WH024';
    END IF;
    IF p_offer IS NULL OR p_offer='00000000-0000-0000-0000-000000000000'::uuid OR p_expires IS NULL OR
       pg_catalog.jsonb_typeof(p_subject) IS DISTINCT FROM 'object' OR octet_length(p_subject::text)>2048 OR
       octet_length(p_offer_hash) IS DISTINCT FROM 32 OR octet_length(p_commit_hash) IS DISTINCT FROM 32 OR
       p_capsule IS NULL OR octet_length(p_capsule) NOT BETWEEN 16 AND 512 THEN
        RAISE EXCEPTION 'Invalid account reset offer' USING ERRCODE='WH023';
    END IF;
    expiry:=pg_catalog.to_timestamp(p_expires::double precision);
    IF expiry<=pg_catalog.clock_timestamp() OR expiry>pg_catalog.clock_timestamp()+interval '1 day' THEN
        RAISE EXCEPTION 'Invalid account reset expiry' USING ERRCODE='WH023';
    END IF;
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND OR NOT actor.custodian OR actor.recipient_signature IS NULL THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    subject:=wormhole_data.account_reset_target(p_subject->>'loginName');
    IF p_subject IS DISTINCT FROM subject THEN RAISE EXCEPTION 'Account reset state changed' USING ERRCODE='WH010'; END IF;
    target_id:=(subject->>'userId')::uuid;
    login:='wh_{{TAG}}_r_'||p_offer::text;
    SELECT * INTO previous FROM wormhole_data.account_reset_offers WHERE id=p_offer FOR SHARE NOWAIT;
    IF FOUND THEN
        IF previous.retired_at IS NULL AND previous.issuer_id=actor.actor AND previous.subject=subject AND previous.expires_at=expiry
           AND previous.offer_hash=p_offer_hash AND previous.commit_hash=p_commit_hash
           AND previous.policy_hash=p_policy_digest AND previous.tls_hash=p_tls_digest AND previous.capsule=p_capsule
           AND EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=previous.role_oid AND r.rolname=previous.role_name AND r.rolcanlogin) THEN
            RETURN login;
        END IF;
        RAISE EXCEPTION 'Account reset offer already exists' USING ERRCODE='WH023';
    END IF;
    PERFORM * FROM wormhole_data.parse_scram_verifier(p_verifier);
    FOR previous IN SELECT id FROM wormhole_data.account_reset_offers WHERE user_id=target_id AND retired_at IS NULL LOOP
        PERFORM wormhole_data.retire_account_reset(previous.id);
    END LOOP;
    BEGIN
        EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L VALID UNTIL %L',
            login,p_verifier,expiry);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Account reset role could not be created' USING ERRCODE='WH023';
    END;
    EXECUTE pg_catalog.format('GRANT wh_{{TAG}}_enroll TO %I WITH INHERIT TRUE, SET FALSE',login);
    SELECT oid INTO STRICT new_oid FROM pg_catalog.pg_roles WHERE rolname=login;
    INSERT INTO wormhole_data.account_reset_offers(id,user_id,issuer_id,role_oid,role_name,expires_at,subject,
        offer_hash,commit_hash,policy_hash,tls_hash,capsule)
    VALUES(p_offer,target_id,actor.actor,new_oid,login,expiry,subject,p_offer_hash,p_commit_hash,p_policy_digest,p_tls_digest,p_capsule);
    PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'publish_account_reset','issued');
    RETURN login;
END
$publish$;

CREATE FUNCTION wormhole_api_v1.account_reset_capsule(p_offer uuid,p_offer_hash bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $capsule$
DECLARE request wormhole_data.account_reset_offers; meta record;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Unsupported workspace transaction isolation' USING ERRCODE='WH006';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    SELECT * INTO request FROM wormhole_data.account_reset_offers r WHERE r.id=p_offer
      AND r.role_name=session_user AND r.retired_at IS NULL AND r.expires_at>pg_catalog.clock_timestamp() FOR SHARE NOWAIT;
    IF NOT FOUND OR request.offer_hash IS DISTINCT FROM p_offer_hash OR meta.state<>'ready' OR
       meta.tls_bundle IS NULL OR pg_catalog.sha256(meta.tls_bundle) IS DISTINCT FROM request.tls_hash OR
       pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM request.policy_hash OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) OR
       NOT EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=request.role_oid AND r.rolname=request.role_name AND r.rolcanlogin
          AND r.rolvaliduntil=request.expires_at AND NOT r.rolsuper AND NOT r.rolcreaterole) OR
       request.subject IS DISTINCT FROM wormhole_data.account_reset_target(request.subject->>'loginName') THEN
        RAISE EXCEPTION 'Account reset unavailable' USING ERRCODE='WH023';
    END IF;
    PERFORM wormhole_data.audit_server_ca(request.user_id,request.id,'reset-v1','account_reset_capsule','released');
    RETURN request.capsule;
END
$capsule$;

REVOKE ALL ON FUNCTION wormhole_data.account_reset_target(text),wormhole_data.retire_account_reset(uuid)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_reset_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text),
    wormhole_api_v1.account_reset_publication_ready(),
    wormhole_api_v1.publish_account_reset(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,jsonb,bigint,bytea,bytea,bytea,text),
    wormhole_api_v1.account_reset_capsule(uuid,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reset_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text),
    wormhole_api_v1.account_reset_publication_ready(),
    wormhole_api_v1.publish_account_reset(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,jsonb,bigint,bytea,bytea,bytea,text)
    TO wh_{{TAG}}_user;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_reset_capsule(uuid,bytea) TO wh_{{TAG}}_enroll;

{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=52 WHERE singleton;
COMMIT;
