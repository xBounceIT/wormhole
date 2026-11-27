-- Version 90: authenticate suspension rotation requests across custodians.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>89 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Retain the exact preimage committed by the signed group-key manifest. A
-- custodian must be able to verify the old membership after account changes.
ALTER TABLE wormhole_data.groups ADD COLUMN key_roster bytea CHECK(octet_length(key_roster)<=3145728);
CREATE FUNCTION wormhole_data.retain_group_key_roster() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $retain$
DECLARE roster record; manifest jsonb;
BEGIN
    NEW.key_roster:=NULL;
    IF NEW.key_manifest IS NULL THEN RETURN NEW; END IF;
    manifest:=convert_from(NEW.key_manifest,'UTF8')::jsonb;
    SELECT * INTO STRICT roster FROM wormhole_data.group_key_roster(NEW.id);
    IF roster.status IN ('ready','no-members') THEN
        NEW.key_roster:=coalesce(roster.body,convert_to('[]','UTF8'));
        IF encode(wormhole_data.group_key_review(NEW.id,(manifest->>'groupRevision')::bigint,NEW.key_roster),'base64')
            IS DISTINCT FROM manifest->>'rosterDigest' THEN NEW.key_roster:=NULL; END IF;
    END IF;
    RETURN NEW;
END
$retain$;
CREATE TRIGGER retain_group_key_roster BEFORE UPDATE OF key_manifest ON wormhole_data.groups
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.retain_group_key_roster();
{{GROUP_ROSTER_AT_SUSPENSION}}
REVOKE ALL ON FUNCTION wormhole_data.retain_group_key_roster(),wormhole_data.group_roster_at_suspension(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION wormhole_api_v1.suspension_signed_roster(p_capability bytea,p_group uuid,p_account uuid,p_suspension bigint)
RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $prior$
DECLARE identity record; cached bytea; previous record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS (SELECT FROM wormhole_data.current_connection_tls() t WHERE t.ssl) THEN RETURN NULL; END IF;
    SELECT g.key_roster INTO cached FROM wormhole_data.groups g WHERE g.id=p_group AND EXISTS (
        SELECT FROM wormhole_data.account_suspensions s JOIN wormhole_data.users u ON u.id=s.account_id
        JOIN wormhole_data.account_suspension_roots r ON r.account_id=s.account_id
        WHERE u.disabled AND s.account_id=p_account AND s.revision=p_suspension AND g.id=ANY(r.groups)
          AND (wormhole_data.effective_boundary_permissions(identity.user_id,r.boundary_id)&17)=17);
    IF NOT FOUND OR cached IS NOT NULL THEN RETURN cached; END IF;
    -- Groups issued before schema 90 lack a cached preimage. Reconstruct it;
    -- the caller still needs the exact digest from the signed manifest.
    SELECT * INTO STRICT previous FROM wormhole_data.group_roster_at_suspension(p_group,p_account);
    IF previous.status IN ('ready','no-members') THEN RETURN coalesce(previous.body,convert_to('[]','UTF8')); END IF;
    RETURN NULL;
EXCEPTION WHEN lock_not_available THEN RETURN NULL;
END
$prior$;

ALTER TABLE wormhole_data.account_suspensions ADD COLUMN rotation_actor uuid,
    ADD COLUMN rotation_epoch bigint, ADD COLUMN rotation_signature bytea,
    ADD CHECK (num_nonnulls(rotation_actor,rotation_epoch,rotation_signature)=0 OR
        (num_nonnulls(rotation_actor,rotation_epoch,rotation_signature)=3 AND rotation_actor<>account_id
         AND rotation_epoch>0 AND revision>=2 AND octet_length(rotation_signature)=64));

CREATE FUNCTION wormhole_api_v1.suspension_rotation_signer(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy bytea,p_state bytea)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $signer$
DECLARE selected record;
BEGIN
    IF NOT (SELECT require_tls FROM wormhole_data.workspace_meta WHERE singleton) THEN RETURN; END IF;
    SELECT * INTO STRICT selected FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy,p_state,false);
    RETURN QUERY SELECT * FROM wormhole_data.server_ca_org_copy(selected.actor,p_holder,p_holder_version,
        p_signer,p_signer_version,'org-sign');
    PERFORM wormhole_data.audit_server_ca(selected.actor,selected.session_id,selected.app_version,
        'suspension_rotation_signer','key_copy_released');
EXCEPTION WHEN SQLSTATE 'WH020' THEN
    -- Administrators without organisation custody can still suspend an account.
    RETURN;
END
$signer$;

CREATE FUNCTION wormhole_api_v1.suspend_account(p_capability bytea,p_account uuid,p_revision bigint,
    p_epoch bigint,p_signature bytea,p_policy bytea,p_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $suspend$
DECLARE actor record; meta record; signer record; message bytea;
BEGIN
    IF p_revision IS NULL OR p_revision<1 OR p_revision=9223372036854775807 OR p_epoch IS NULL OR p_epoch<1
        OR octet_length(p_signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid suspension authorization' USING ERRCODE='22023';
    END IF;
    -- workspace_access checks the current principal, TLS, policy, account and reviewed
    -- revision and holds the necessary locks until the receipt commits with it.
    SELECT a.status,a.payload INTO STRICT status,payload FROM wormhole_api_v1.workspace_access(
        p_capability,'disable-account',p_account,p_revision,p_policy,p_state) a;
    IF status='changed' THEN
        SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
        SELECT workspace_id,epoch INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
        SELECT k.key_id,k.key_version,k.public_key INTO STRICT signer FROM wormhole_data.keys k
            WHERE k.kind='org-sign' AND k.owner_id IS NULL AND k.status='active' AND k.suite=1 FOR SHARE NOWAIT;
        message:=convert_to('wormhole/v1/suspension-rotation','UTF8')||decode('00','hex')||
            uuid_send(meta.workspace_id)||int8send(meta.epoch)||uuid_send(actor.user_id)||uuid_send(p_account)||
            int8send(p_revision+1)||uuid_send(signer.key_id)||int4send(signer.key_version);
        IF meta.epoch IS DISTINCT FROM p_epoch OR wormhole_data.ed25519_verify(signer.public_key,message,p_signature) IS NOT TRUE THEN
            RAISE EXCEPTION 'Invalid suspension authorization' USING ERRCODE='WH023';
        END IF;
        UPDATE wormhole_data.account_suspensions SET rotation_actor=actor.user_id,rotation_epoch=p_epoch,
            rotation_signature=p_signature WHERE account_id=p_account AND revision=p_revision+1;
        IF NOT FOUND THEN RAISE EXCEPTION 'Suspension inventory changed' USING ERRCODE='WH023'; END IF;
    END IF;
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::jsonb;
END
$suspend$;

CREATE FUNCTION wormhole_api_v1.suspension_rotation_receipts(p_capability bytea,p_epoch bigint,p_after uuid)
RETURNS TABLE(actor_id uuid,account_id uuid,revision bigint,signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $receipts$
DECLARE identity record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS (SELECT FROM wormhole_data.current_connection_tls() t WHERE t.ssl) THEN RETURN; END IF;
    RETURN QUERY SELECT s.rotation_actor,s.account_id,s.revision,s.rotation_signature
        FROM wormhole_data.account_suspensions s JOIN wormhole_data.users u ON u.id=s.account_id
        JOIN wormhole_data.workspace_meta m ON m.singleton AND m.epoch=p_epoch AND m.state='ready'
        WHERE u.disabled AND s.rotation_epoch=p_epoch AND (p_after IS NULL OR s.account_id>p_after)
          AND EXISTS (SELECT FROM wormhole_data.account_suspension_roots r
              JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(r.root_id,r.root_version)
              WHERE r.account_id=s.account_id AND (k.status='active' OR
                  EXISTS (SELECT FROM wormhole_data.group_members g WHERE g.group_id=ANY(r.groups) AND g.user_id=s.account_id)
                  OR EXISTS (SELECT FROM wormhole_data.group_member_rotation_jobs j WHERE j.group_id=ANY(r.groups)
                      AND j.removed_user_id=s.account_id AND NOT j.complete)))
        ORDER BY s.account_id LIMIT 25;
EXCEPTION WHEN lock_not_available THEN
    RETURN;
END
$receipts$;

REVOKE ALL ON FUNCTION wormhole_api_v1.suspension_rotation_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.suspension_signed_roster(bytea,uuid,uuid,bigint),
    wormhole_api_v1.suspend_account(bytea,uuid,bigint,bigint,bytea,bytea,bytea),
    wormhole_api_v1.suspension_rotation_receipts(bytea,bigint,uuid)
    FROM PUBLIC,wh_{{TAG}}_enroll,wh_{{TAG}}_admin,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.suspension_rotation_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea),
    wormhole_api_v1.suspension_signed_roster(bytea,uuid,uuid,bigint),
    wormhole_api_v1.suspend_account(bytea,uuid,bigint,bigint,bytea,bytea,bytea),
    wormhole_api_v1.suspension_rotation_receipts(bytea,bigint,uuid)
    TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=90 WHERE singleton;
COMMIT;
