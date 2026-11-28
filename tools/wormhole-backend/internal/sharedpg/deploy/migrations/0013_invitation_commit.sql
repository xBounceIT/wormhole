-- Version 13: first-user enrollment transaction. Reset is a separate operation.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>12 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;
SET LOCAL ROLE NONE;
GRANT wh_{{TAG}}_user TO wh_{{TAG}}_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
SET LOCAL ROLE wh_{{TAG}}_owner;

-- A consumed bootstrap no longer needs its code-wrapped private key capsule.
ALTER TABLE wormhole_data.invites ALTER COLUMN bootstrap_envelope DROP NOT NULL;
ALTER TABLE wormhole_data.invites ADD CONSTRAINT invites_pending_bootstrap
    CHECK(bootstrap_envelope IS NOT NULL OR used_at IS NOT NULL);

CREATE FUNCTION wormhole_api_v1.commit_invitation(p_invite uuid,p_revision bigint,p_digest bytea,
    p_device uuid,p_name text,p_verifier text,p_kdf text,p_ask boolean,
    p_nonce bytea,p_ciphertext bytea,p_certificate bytea,p_copies jsonb)
RETURNS TABLE(device_id uuid,role_name text,wrap_revision bigint,auth_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $commit$
DECLARE invitation record; bootstrap record; parsed record; chain jsonb; manifest jsonb;
    enc_id uuid; sign_id uuid; enc_public bytea; sign_public bytea; target text;
    source record; item jsonb; matches integer; copies_count integer:=0; account_state record;
    state_doc jsonb; policy_doc jsonb; required_kdf integer; actual_kdf integer;
BEGIN
    IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Unsupported workspace transaction isolation' USING ERRCODE='WH006';
    END IF;
    -- Exclusive invitation lock is acquired before the shared authorization gate.
    -- A second redemption fails NOWAIT or sees the already consumed invitation.
    SELECT * INTO invitation FROM wormhole_data.invites WHERE id=p_invite FOR UPDATE NOWAIT;
    IF NOT FOUND OR invitation.kind<>'invite' THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    SELECT * INTO STRICT bootstrap FROM wormhole_api_v1.enrollment_bootstrap(p_invite);
    IF p_revision IS NULL OR p_revision<>bootstrap.manifest_revision OR p_digest IS NULL
        OR pg_catalog.octet_length(p_digest)<>32 OR pg_catalog.sha256(bootstrap.manifest)<>p_digest THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    PERFORM 1 FROM wormhole_data.users WHERE id=invitation.user_id FOR UPDATE NOWAIT;
    IF EXISTS(SELECT 1 FROM wormhole_data.account_auth WHERE user_id=invitation.user_id)
        OR EXISTS(SELECT 1 FROM wormhole_data.user_key_wraps WHERE user_id=invitation.user_id)
        OR EXISTS(SELECT 1 FROM wormhole_data.devices WHERE user_id=invitation.user_id)
        OR EXISTS(SELECT 1 FROM wormhole_data.user_enrollments WHERE user_id=invitation.user_id) THEN
        RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012';
    END IF;
    IF p_device IS NULL OR p_device='00000000-0000-0000-0000-000000000000'::uuid
        OR p_name IS NULL OR pg_catalog.octet_length(p_name) NOT BETWEEN 1 AND 4096
        OR p_kdf IS NULL OR p_kdf NOT IN ('kdf-low','kdf-v1','kdf-v2','kdf-v3') OR p_ask IS NULL
        OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce)<>12
        OR p_ciphertext IS NULL OR pg_catalog.octet_length(p_ciphertext)<>81
        OR p_certificate IS NULL OR pg_catalog.octet_length(p_certificate) NOT BETWEEN 1 AND 1064960
        OR p_copies IS NULL OR pg_catalog.jsonb_typeof(p_copies)<>'array' THEN
        RAISE EXCEPTION 'Invalid enrollment payload' USING ERRCODE='WH012';
    END IF;
    IF pg_catalog.jsonb_array_length(p_copies)>1024 OR pg_catalog.octet_length(p_copies::text)>1048576 THEN
        RAISE EXCEPTION 'Invalid enrollment payload' USING ERRCODE='WH012';
    END IF;
    SELECT * INTO STRICT parsed FROM wormhole_data.parse_scram_verifier(p_verifier);
    -- Only public certification and ciphertext are accepted. The code-authenticated
    -- role authorizes this choice; native clients independently verify signatures.
    BEGIN
        chain:=pg_catalog.convert_from(p_certificate,'UTF8')::jsonb;
        manifest:=pg_catalog.convert_from(bootstrap.manifest,'UTF8')::jsonb;
        enc_id:=(chain->'rekey'->>'encryptionKeyId')::uuid;
        sign_id:=(chain->'rekey'->>'signingKeyId')::uuid;
        enc_public:=pg_catalog.decode(chain->'rekey'->'public'->>'encryption','base64');
        sign_public:=pg_catalog.decode(chain->'rekey'->'public'->>'signing','base64');
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid enrollment payload' USING ERRCODE='WH012';
    END;
    IF chain->>'formatVersion' IS DISTINCT FROM '1' OR chain->'manifest' IS DISTINCT FROM manifest
        OR chain->'rekey'->>'formatVersion' IS DISTINCT FROM '1' OR chain->'rekey'->>'keyVersion' IS DISTINCT FROM '1'
        OR enc_id IS NULL OR sign_id IS NULL OR enc_id=sign_id
        OR enc_id='00000000-0000-0000-0000-000000000000'::uuid OR sign_id='00000000-0000-0000-0000-000000000000'::uuid
        OR enc_id IN(invitation.bootstrap_enc_key_id,invitation.bootstrap_sign_key_id)
        OR sign_id IN(invitation.bootstrap_enc_key_id,invitation.bootstrap_sign_key_id)
        OR enc_public IS NULL OR pg_catalog.octet_length(enc_public)<>32
        OR sign_public IS NULL OR pg_catalog.octet_length(sign_public)<>32 THEN
        RAISE EXCEPTION 'Invalid enrollment payload' USING ERRCODE='WH012';
    END IF;
    SELECT * INTO account_state FROM wormhole_data.user_key_states WHERE user_id=invitation.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    BEGIN
        state_doc:=pg_catalog.convert_from(account_state.signed_state,'UTF8')::jsonb;
        SELECT pg_catalog.convert_from(m.signed_profile,'UTF8')::jsonb->'policy' INTO policy_doc
            FROM wormhole_data.workspace_meta m WHERE singleton;
        IF state_doc->>'formatVersion' IS DISTINCT FROM '1' OR state_doc->>'active' IS DISTINCT FROM 'true'
            OR state_doc->>'sequence' IS DISTINCT FROM account_state.state_sequence::text
            OR state_doc->>'workspaceId' IS DISTINCT FROM bootstrap.workspace_id::text
            OR state_doc->>'userId' IS DISTINCT FROM invitation.user_id::text
            OR state_doc->'encryption'->>'id' IS DISTINCT FROM invitation.bootstrap_enc_key_id::text
            OR state_doc->'encryption'->>'version' IS DISTINCT FROM invitation.bootstrap_enc_key_version::text
            OR state_doc->'signing'->>'id' IS DISTINCT FROM invitation.bootstrap_sign_key_id::text
            OR state_doc->'signing'->>'version' IS DISTINCT FROM invitation.bootstrap_sign_key_version::text
            OR chain->'bootstrapEncryption'->'signer' IS DISTINCT FROM state_doc->'signer'
            OR chain->'bootstrapSigning'->'signer' IS DISTINCT FROM state_doc->'signer'
            OR COALESCE((state_doc->>'minimumEncryptionCertificate')::bigint,0)<1
            OR COALESCE((state_doc->>'minimumSigningCertificate')::bigint,0)<1
            OR COALESCE((chain->'bootstrapEncryption'->>'revision')::bigint,0)<(state_doc->>'minimumEncryptionCertificate')::bigint
            OR COALESCE((chain->'bootstrapSigning'->>'revision')::bigint,0)<(state_doc->>'minimumSigningCertificate')::bigint THEN
            RAISE EXCEPTION 'Account enrollment state changed';
        END IF;
        -- The metadata row is locked by enrollment_bootstrap. Recheck current
        -- floors here: an earlier native download cannot authorize a downgrade.
        required_kdf:=CASE policy_doc->>'kdf' WHEN 'kdf-low' THEN 0 WHEN 'kdf-v1' THEN 1 WHEN 'kdf-v2' THEN 2 WHEN 'kdf-v3' THEN 3 END;
        actual_kdf:=CASE p_kdf WHEN 'kdf-low' THEN 0 WHEN 'kdf-v1' THEN 1 WHEN 'kdf-v2' THEN 2 WHEN 'kdf-v3' THEN 3 END;
        IF policy_doc IS NULL OR policy_doc->>'formatVersion' IS DISTINCT FROM '1'
            OR policy_doc->>'workspaceId' IS DISTINCT FROM bootstrap.workspace_id::text
            OR required_kdf IS NULL OR actual_kdf<required_kdf
            OR policy_doc->>'profile' IS NULL OR policy_doc->>'profile' NOT IN ('default','standard','hardened','paranoid')
            OR policy_doc->>'askRequired' IS NULL OR policy_doc->>'askRequired' NOT IN ('true','false')
            OR (policy_doc->>'askRequired'='true' AND NOT p_ask)
            OR (p_kdf='kdf-low' AND (policy_doc->>'profile'<>'default' OR policy_doc->>'lowKdfApproved' IS DISTINCT FROM 'true'))
            OR (policy_doc->>'profile'='hardened' AND (required_kdf<2 OR (NOT p_ask AND EXISTS(SELECT 1 FROM wormhole_data.users WHERE id=invitation.user_id AND is_admin))))
            OR (policy_doc->>'profile'='paranoid' AND (required_kdf<>3 OR NOT p_ask)) THEN
            RAISE EXCEPTION 'Account enrollment policy changed';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Account enrollment requirements changed' USING ERRCODE='WH010';
    END;
    -- Lock the bootstrap parent to prevent inserting new holder copies while the
    -- complete source set is checked. Existing copies are individually locked.
    PERFORM 1 FROM wormhole_data.keys WHERE key_id=invitation.bootstrap_enc_key_id
        AND key_version=invitation.bootstrap_enc_key_version AND kind='user-enc'
        AND owner_id=invitation.user_id AND status='pending' FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    PERFORM 1 FROM wormhole_data.keys WHERE key_id=invitation.bootstrap_sign_key_id
        AND key_version=invitation.bootstrap_sign_key_version AND kind='user-sign'
        AND owner_id=invitation.user_id AND status='pending' FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='WH012'; END IF;
    FOR source IN SELECT c.* FROM wormhole_data.key_copies c
        WHERE c.holder_key_id=invitation.bootstrap_enc_key_id AND c.holder_key_version=invitation.bootstrap_enc_key_version
        ORDER BY c.key_id,c.key_version LIMIT 1025 FOR UPDATE NOWAIT LOOP
        copies_count:=copies_count+1;
        SELECT count(*) INTO matches FROM pg_catalog.jsonb_array_elements(p_copies) e
            WHERE e->>'keyId'=source.key_id::text AND e->>'keyVersion'=source.key_version::text;
        IF copies_count>1024 OR matches<>1 THEN RAISE EXCEPTION 'Incomplete enrollment copies' USING ERRCODE='WH012'; END IF;
    END LOOP;
    IF copies_count<>pg_catalog.jsonb_array_length(p_copies) THEN
        RAISE EXCEPTION 'Incomplete enrollment copies' USING ERRCODE='WH012';
    END IF;
    INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,public_key)
        VALUES(enc_id,1,'user-enc',invitation.user_id,2,enc_public),(sign_id,1,'user-sign',invitation.user_id,1,sign_public);
    FOR item IN SELECT * FROM pg_catalog.jsonb_array_elements(p_copies) LOOP
        BEGIN
            IF pg_catalog.octet_length(pg_catalog.decode(item->>'enc','hex')) IS DISTINCT FROM 32
                OR pg_catalog.octet_length(pg_catalog.decode(item->>'ciphertext','hex')) IS DISTINCT FROM 48
                OR pg_catalog.octet_length(pg_catalog.decode(item->>'signature','hex')) IS DISTINCT FROM 64 THEN
                RAISE EXCEPTION 'Invalid copy';
            END IF;
            INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature)
            VALUES((item->>'keyId')::uuid,(item->>'keyVersion')::integer,enc_id,1,2,
                pg_catalog.decode(item->>'enc','hex'),pg_catalog.decode(item->>'ciphertext','hex'),sign_id,1,pg_catalog.decode(item->>'signature','hex'));
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'Invalid enrollment copy' USING ERRCODE='WH012';
        END;
    END LOOP;
    DELETE FROM wormhole_data.key_copies WHERE holder_key_id=invitation.bootstrap_enc_key_id AND holder_key_version=invitation.bootstrap_enc_key_version;
    UPDATE wormhole_data.keys SET status='retired' WHERE (key_id,key_version) IN
        ((invitation.bootstrap_enc_key_id,invitation.bootstrap_enc_key_version),(invitation.bootstrap_sign_key_id,invitation.bootstrap_sign_key_version));
    target:='wh_{{TAG}}_d_'||p_device::text;
    -- Never adopt an existing role. Transactional DDL rolls back with every row.
    EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L VALID UNTIL %L',target,p_verifier,invitation.expires_at);
    EXECUTE pg_catalog.format('GRANT wh_{{TAG}}_user TO %I WITH INHERIT TRUE, SET FALSE',target);
    INSERT INTO wormhole_data.devices(id,user_id,role_name,name,status) VALUES(p_device,invitation.user_id,target,p_name,'active');
    INSERT INTO wormhole_data.account_auth(user_id,iterations,salt,stored_key,server_key)
        VALUES(invitation.user_id,parsed.iterations,parsed.salt,parsed.stored_key,parsed.server_key);
    INSERT INTO wormhole_data.user_key_wraps(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,kdf_preset,ask_required,nonce,ciphertext)
        VALUES(invitation.user_id,enc_id,1,sign_id,1,p_kdf,p_ask,p_nonce,p_ciphertext);
    INSERT INTO wormhole_data.user_enrollments(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,certificate)
        VALUES(invitation.user_id,enc_id,1,sign_id,1,p_certificate);
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
            VALUES(invitation.user_id,pg_catalog.gen_random_uuid(),session_user,'ui','join_workspace','success',pg_catalog.inet_client_addr(),'enrollment-v1');
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    UPDATE wormhole_data.invites SET used_at=pg_catalog.clock_timestamp(),bootstrap_envelope=NULL WHERE id=p_invite;
    RETURN QUERY SELECT p_device,target,1::bigint,1::bigint;
END
$commit$;
REVOKE ALL ON FUNCTION wormhole_api_v1.commit_invitation(uuid,bigint,bytea,uuid,text,text,text,boolean,bytea,bytea,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.commit_invitation(uuid,bigint,bytea,uuid,text,text,text,boolean,bytea,bytea,bytea,jsonb) TO wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=13 WHERE singleton;
COMMIT;
