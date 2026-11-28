-- Version 51: organisation-certified escrow recipient and account-owned copies.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>50 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.account_recovery_context(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,p_write boolean)
RETURNS TABLE(actor uuid,session_id uuid,app_version text,custodian boolean,
    recipient_id uuid,recipient_version integer,recipient_public bytea,
    organisation_signer uuid,organisation_version integer,recipient_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
AS $context$
DECLARE identity record; meta record; recipient record; signer record; profile jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_write THEN
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    END IF;
    IF meta.state<>'ready' OR NOT meta.require_tls OR
       NOT COALESCE((SELECT ssl FROM wormhole_data.current_connection_tls()),false) OR
       meta.tls_sequence<1 OR meta.tls_sequence IS DISTINCT FROM p_tls_sequence OR
       pg_catalog.sha256(meta.tls_bundle) IS DISTINCT FROM p_tls_digest OR
       pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM p_policy_digest THEN
        RAISE EXCEPTION 'Workspace recovery trust changed' USING ERRCODE='WH011';
    END IF;
    profile:=pg_catalog.convert_from(meta.signed_profile,'UTF8')::jsonb->'policy';
    IF NOT COALESCE(profile->>'orgEscrow'='true' AND profile->>'profile' IN ('default','standard'),false) THEN
        RETURN;
    END IF;
    PERFORM e.user_id
    FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_states s USING(user_id)
    WHERE e.user_id=identity.user_id AND pg_catalog.sha256(s.signed_state)=p_state_digest AND
       pg_catalog.convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' AND
       (e.encryption_key_id,e.encryption_key_version)=(p_holder,p_holder_version) AND
       (e.signing_key_id,e.signing_key_version)=(p_signer,p_signer_version)
    FOR SHARE OF e,s NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace account state changed' USING ERRCODE='WH010';
    END IF;
    SELECT * INTO STRICT recipient FROM wormhole_data.keys
    WHERE kind='org-enc' AND owner_id IS NULL AND status='active' AND suite=2 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    SELECT k.key_id,k.key_version INTO STRICT signer FROM wormhole_data.keys k
    WHERE kind='org-sign' AND owner_id IS NULL AND status='active' AND suite=1 AND octet_length(public_key)=32 FOR SHARE NOWAIT;
    IF recipient.cert_signature IS NOT NULL AND (
        recipient.cert_revision IS DISTINCT FROM 1 OR
        (recipient.cert_signer_key_id,recipient.cert_signer_key_version) IS DISTINCT FROM (signer.key_id,signer.key_version)
    ) THEN
        RAISE EXCEPTION 'Organisation recovery recipient is unavailable' USING ERRCODE='WH023';
    END IF;
    RETURN QUERY SELECT identity.user_id,s.id,s.app_version,
        u.is_admin AND (
            SELECT count(*)=2 FROM wormhole_data.key_copies c
            WHERE (c.key_id,c.key_version) IN ((recipient.key_id,recipient.key_version),(signer.key_id,signer.key_version))
              AND (c.holder_key_id,c.holder_key_version)=(p_holder,p_holder_version)
              AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version)
              AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
        ),recipient.key_id,recipient.key_version,recipient.public_key,
        signer.key_id,signer.key_version,recipient.cert_signature
    FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
    -- require_device holds a share lock on this row. Use the locked membership
    -- rather than the earlier role snapshot from device identification.
    JOIN wormhole_data.users u ON u.id=identity.user_id AND NOT u.disabled
    WHERE a.device_id=identity.device_id;
END
$context$;

CREATE FUNCTION wormhole_api_v1.account_recovery_material(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $material$
DECLARE selected record; self_copies jsonb; organisation_copies jsonb:='[]'::jsonb;
BEGIN
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,false);
    IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
    SELECT COALESCE(pg_catalog.jsonb_agg(item.body ORDER BY item.body->>'id'),'[]'::jsonb) INTO self_copies
    FROM (SELECT pg_catalog.jsonb_build_object('id',c.key_id,'version',c.key_version,
                'enc',pg_catalog.encode(c.enc,'base64'),'ciphertext',pg_catalog.encode(c.ciphertext,'base64'),
                'signature',pg_catalog.encode(c.signature,'base64')) AS body
        FROM wormhole_data.key_copies c
        WHERE (c.key_id,c.key_version) IN ((p_holder,p_holder_version),(p_signer,p_signer_version))
          AND (c.holder_key_id,c.holder_key_version)=(selected.recipient_id,selected.recipient_version)
          AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version)
          AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
        FOR SHARE NOWAIT) item;
    IF pg_catalog.jsonb_array_length(self_copies)>0 THEN
        PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,
            'read_account_recovery','account_copies_released');
    END IF;
    IF selected.recipient_signature IS NULL AND selected.custodian THEN
        SELECT COALESCE(pg_catalog.jsonb_agg(item.body ORDER BY item.body->>'id'),'[]'::jsonb) INTO organisation_copies
        FROM (SELECT pg_catalog.jsonb_build_object('id',c.key_id,'version',c.key_version,
                    'enc',pg_catalog.encode(c.enc,'base64'),'ciphertext',pg_catalog.encode(c.ciphertext,'base64'),
                    'signature',pg_catalog.encode(c.signature,'base64')) AS body
            FROM wormhole_data.key_copies c
            WHERE (c.key_id,c.key_version) IN ((selected.recipient_id,selected.recipient_version),
                                             (selected.organisation_signer,selected.organisation_version))
              AND (c.holder_key_id,c.holder_key_version)=(p_holder,p_holder_version)
              AND (c.issuer_key_id,c.issuer_key_version)=(p_signer,p_signer_version)
              AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48
            FOR SHARE NOWAIT) item;
        IF pg_catalog.jsonb_array_length(organisation_copies)=2 THEN
            PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,
                'certify_recovery_recipient','organisation_copies_released');
        ELSE
            organisation_copies:='[]'::jsonb;
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
      'recipient',pg_catalog.jsonb_build_object('id',selected.recipient_id,'version',selected.recipient_version),
      'signer',pg_catalog.jsonb_build_object('id',selected.organisation_signer,'version',selected.organisation_version),
      'publicKey',pg_catalog.encode(selected.recipient_public,'base64'),
      'certificate',pg_catalog.encode(selected.recipient_signature,'base64'),
      'organisationCopies',organisation_copies,'accountCopies',self_copies);
END
$material$;

CREATE FUNCTION wormhole_api_v1.store_account_recovery(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_policy_digest bytea,p_state_digest bytea,
    p_recipient uuid,p_recipient_version integer,p_certificate bytea,p_copies jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $store$
DECLARE selected record; record_copy jsonb; copy_id uuid; copy_version integer;
        enc bytea; ciphertext bytea; signature bytea; found_encryption boolean:=false; found_signing boolean:=false;
BEGIN
    SELECT * INTO selected FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy_digest,p_state_digest,true);
    IF NOT FOUND OR (selected.recipient_id,selected.recipient_version) IS DISTINCT FROM (p_recipient,p_recipient_version) OR
       pg_catalog.jsonb_typeof(p_copies) IS DISTINCT FROM 'array' OR pg_catalog.octet_length(p_copies::text)>2048 THEN
        RAISE EXCEPTION 'Account recovery is unavailable' USING ERRCODE='WH023';
    END IF;
    IF pg_catalog.jsonb_array_length(p_copies)<>2 THEN
        RAISE EXCEPTION 'Both current account key copies are required' USING ERRCODE='WH023';
    END IF;
    IF selected.recipient_signature IS NULL THEN
        IF NOT selected.custodian OR octet_length(p_certificate) IS DISTINCT FROM 64 THEN
            RAISE EXCEPTION 'Certified organisation recovery recipient required' USING ERRCODE='WH023';
        END IF;
        UPDATE wormhole_data.keys SET cert_signer_key_id=selected.organisation_signer,
          cert_signer_key_version=selected.organisation_version,cert_revision=1,cert_signature=p_certificate
        WHERE (key_id,key_version)=(p_recipient,p_recipient_version) AND cert_signature IS NULL;
    ELSIF p_certificate IS DISTINCT FROM selected.recipient_signature THEN
        RAISE EXCEPTION 'Organisation recovery recipient changed' USING ERRCODE='WH023';
    END IF;
    FOR record_copy IN SELECT * FROM pg_catalog.jsonb_array_elements(p_copies) LOOP
        copy_id:=(record_copy->>'id')::uuid; copy_version:=(record_copy->>'version')::integer;
        enc:=pg_catalog.decode(record_copy->>'enc','base64');
        ciphertext:=pg_catalog.decode(record_copy->>'ciphertext','base64');
        signature:=pg_catalog.decode(record_copy->>'signature','base64');
        IF octet_length(enc) IS DISTINCT FROM 32 OR octet_length(ciphertext) IS DISTINCT FROM 48 OR
           octet_length(signature) IS DISTINCT FROM 64 THEN
            RAISE EXCEPTION 'Invalid account recovery copy' USING ERRCODE='WH023';
        END IF;
        IF (copy_id,copy_version)=(p_holder,p_holder_version) AND NOT found_encryption THEN
            found_encryption:=true;
        ELSIF (copy_id,copy_version)=(p_signer,p_signer_version) AND NOT found_signing THEN
            found_signing:=true;
        ELSE
            RAISE EXCEPTION 'Invalid account recovery copy identity' USING ERRCODE='WH023';
        END IF;
        INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,
            issuer_key_id,issuer_key_version,signature)
        VALUES(copy_id,copy_version,p_recipient,p_recipient_version,2,enc,ciphertext,p_signer,p_signer_version,signature)
        ON CONFLICT(key_id,key_version,holder_key_id,holder_key_version) DO UPDATE SET
            suite=2,enc=EXCLUDED.enc,ciphertext=EXCLUDED.ciphertext,issuer_key_id=EXCLUDED.issuer_key_id,
            issuer_key_version=EXCLUDED.issuer_key_version,signature=EXCLUDED.signature;
    END LOOP;
    PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,
        'store_account_recovery','escrow_written');
    RETURN 'stored';
END
$store$;

REVOKE ALL ON FUNCTION wormhole_data.account_recovery_context(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_recovery_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.store_account_recovery(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer,bytea,jsonb)
    FROM PUBLIC,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_recovery_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.store_account_recovery(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer,bytea,jsonb)
    TO wh_{{TAG}}_user;
{{RESTORE_WORKSPACE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=51 WHERE singleton;
COMMIT;
