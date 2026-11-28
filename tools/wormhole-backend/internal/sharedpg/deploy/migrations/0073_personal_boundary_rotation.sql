-- Version 73: rotate an escrowed personal boundary for its suspended owner.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>72 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Private visibility check for the rotation coordinates only. The native
-- rotation still authenticates the manifest, both custody copies and the
-- retained organisation recipient before it opens any key.
CREATE FUNCTION wormhole_data.personal_account_rotation_available(p_actor uuid,p_account uuid,p_boundary uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $custodian$
    SELECT EXISTS(
        SELECT FROM wormhole_data.workspace_meta m
        JOIN wormhole_data.user_enrollments e ON e.user_id=p_actor
        JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(e.encryption_key_id,e.encryption_key_version)
        JOIN wormhole_data.keys s ON (s.key_id,s.key_version)=(e.signing_key_id,e.signing_key_version)
        JOIN wormhole_data.keys enc ON enc.kind='org-enc' AND enc.owner_id IS NULL AND enc.status='active' AND enc.suite=2
        JOIN wormhole_data.keys signer ON (signer.key_id,signer.key_version)=(enc.cert_signer_key_id,enc.cert_signer_key_version)
        WHERE m.singleton AND m.state='ready' AND m.require_tls AND p_actor<>p_account
            AND p_boundary=wormhole_data.personal_import_boundary_id(m.workspace_id,p_account)
            AND convert_from(m.signed_profile,'UTF8')::jsonb#>>'{policy,orgEscrow}'='true'
            AND convert_from(m.signed_profile,'UTF8')::jsonb#>>'{policy,profile}' IN ('default','standard')
            AND h.kind='user-enc' AND h.owner_id=p_actor AND h.status='active'
            AND s.kind='user-sign' AND s.owner_id=p_actor AND s.status='active'
            AND signer.kind='org-sign' AND signer.owner_id IS NULL AND signer.status='active' AND signer.suite=1
            AND enc.cert_revision=1 AND octet_length(enc.cert_signature)=64
            AND 2=(SELECT count(*) FROM wormhole_data.key_copies c
                WHERE (c.key_id,c.key_version) IN ((enc.key_id,enc.key_version),(signer.key_id,signer.key_version))
                    AND (c.holder_key_id,c.holder_key_version)=(h.key_id,h.key_version)
                    AND (c.issuer_key_id,c.issuer_key_version)=(s.key_id,s.key_version)
                    AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48)
            AND wormhole_data.personal_import_is_escrowed(p_boundary,p_account,enc.key_id,enc.key_version,signer.key_id,signer.key_version)
    )
$custodian$;

-- A rotation intentionally removes the owner's wrap. Keep normal suspension
-- reversible before retirement. After retirement require a current owner
-- wrap, so a successful Enable cannot lead to a writable, unreadable vault.
CREATE FUNCTION wormhole_data.personal_account_recovery_required(p_account uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $restore_access$
    SELECT EXISTS(
        SELECT FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.boundaries b ON b.id=r.boundary_id AND b.owner_user_id=p_account AND NOT b.deleted
        JOIN wormhole_data.keys old ON (old.key_id,old.key_version)=(r.root_id,r.root_version) AND old.status='retired'
        WHERE r.account_id=p_account AND NOT EXISTS(
            SELECT FROM wormhole_data.boundary_manifests m
            CROSS JOIN LATERAL (SELECT convert_from(m.body,'UTF8')::jsonb
                ->(CASE r.purpose WHEN 1 THEN 'view' ELSE 'secret' END) AS root) d
            JOIN wormhole_data.keys current_key ON (current_key.key_id,current_key.key_version)=
                ((d.root#>>'{key,id}')::uuid,(d.root#>>'{key,version}')::integer)
            JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(current_key.key_id,current_key.key_version)
            JOIN wormhole_data.user_enrollments e ON (e.encryption_key_id,e.encryption_key_version)=(c.holder_key_id,c.holder_key_version)
            JOIN wormhole_data.keys h ON (h.key_id,h.key_version)=(c.holder_key_id,c.holder_key_version)
            WHERE m.boundary_id=b.id AND e.user_id=p_account AND h.kind='user-enc' AND h.owner_id=p_account AND h.status='active'
                AND current_key.owner_id=b.id AND current_key.status='active'
                AND (c.issuer_key_id,c.issuer_key_version)=(m.signer_key_id,m.signer_key_version)
                AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48)
    )
$restore_access$;

{{PERSONAL_ACCOUNT_ROTATION_PENDING}}
{{PERSONAL_ACCOUNT_ROTATION_GRAPH}}
{{PERSONAL_ACCOUNT_ROTATION_API}}
{{PERSONAL_ACCOUNT_ROOT_INVENTORY}}
{{PERSONAL_ACCOUNT_ENABLE_GUARD}}
{{SUSPENSION_RESTORE_DEFINITION}}

REVOKE ALL ON FUNCTION wormhole_data.personal_account_rotation_available(uuid,uuid,uuid),
    wormhole_data.personal_account_recovery_required(uuid)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=73 WHERE singleton;
COMMIT;
