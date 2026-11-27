-- Version 77: bind personal recovery to the enrollment captured at suspension.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>76 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.account_suspension_enrollments (
    account_id uuid PRIMARY KEY REFERENCES wormhole_data.account_suspensions(account_id) ON DELETE CASCADE,
    encryption_key_id uuid NOT NULL,
    encryption_key_version integer NOT NULL,
    signing_key_id uuid NOT NULL,
    signing_key_version integer NOT NULL,
    state_sequence bigint NOT NULL CHECK(state_sequence>0),
    state_digest bytea NOT NULL CHECK(octet_length(state_digest)=32),
    FOREIGN KEY(encryption_key_id,encryption_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    FOREIGN KEY(signing_key_id,signing_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);

-- A NULL account is used only when upgrading or restoring a pre-77 workspace.
CREATE FUNCTION wormhole_data.capture_suspension_enrollment(p_account uuid) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $scope$
    INSERT INTO wormhole_data.account_suspension_enrollments
        (account_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,state_sequence,state_digest)
    SELECT selected.account_id,e.encryption_key_id,e.encryption_key_version,e.signing_key_id,e.signing_key_version,
           state.state_sequence,sha256(state.signed_state)
    FROM wormhole_data.account_suspensions selected
    JOIN wormhole_data.user_enrollments e ON e.user_id=selected.account_id
    JOIN wormhole_data.user_key_states state ON state.user_id=selected.account_id
    WHERE p_account IS NULL OR selected.account_id=p_account
    FOR SHARE OF e,state NOWAIT;
$scope$;

DO $backfill$
BEGIN
    PERFORM wormhole_data.capture_suspension_enrollment(NULL);
END
$backfill$;

{{SUSPENSION_CAPTURE_DEFINITION}}

CREATE FUNCTION wormhole_data.suspension_enrollments_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $archive$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.account_suspensions s
        LEFT JOIN wormhole_data.user_enrollments e ON e.user_id=s.account_id
        LEFT JOIN wormhole_data.user_key_states state ON state.user_id=s.account_id
        LEFT JOIN wormhole_data.account_suspension_enrollments p ON p.account_id=s.account_id
        LEFT JOIN wormhole_data.keys enc ON (enc.key_id,enc.key_version)=(p.encryption_key_id,p.encryption_key_version)
        LEFT JOIN wormhole_data.keys sign ON (sign.key_id,sign.key_version)=(p.signing_key_id,p.signing_key_version)
        WHERE (e.user_id IS NULL)<>(p.account_id IS NULL)
           OR (p.account_id IS NOT NULL AND (
               enc.kind<>'user-enc' OR sign.kind<>'user-sign'
               OR enc.owner_id IS DISTINCT FROM s.account_id OR sign.owner_id IS DISTINCT FROM s.account_id
               OR state.user_id IS NULL OR state.state_sequence<p.state_sequence
               OR (state.state_sequence=p.state_sequence AND sha256(state.signed_state)<>p.state_digest)
               OR ((e.signing_key_id,e.signing_key_version)<>(p.signing_key_id,p.signing_key_version) AND NOT EXISTS(
                   SELECT FROM wormhole_data.user_enrollment_history h WHERE h.user_id=s.account_id
                       AND (h.signing_key_id,h.signing_key_version)=(p.signing_key_id,p.signing_key_version)))
           ))
    );
$archive$;

CREATE OR REPLACE FUNCTION wormhole_data.personal_account_recovery_required(p_account uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $restore_access$
    SELECT EXISTS(
        SELECT FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.boundaries b ON b.id=r.boundary_id AND b.owner_user_id=p_account AND NOT b.deleted
        JOIN wormhole_data.keys old ON (old.key_id,old.key_version)=(r.root_id,r.root_version) AND old.status='retired'
        WHERE r.account_id=p_account AND 2<>(
            SELECT count(*)
            FROM wormhole_data.account_suspension_enrollments p
            JOIN wormhole_data.user_enrollment_history history ON history.user_id=p.account_id
                AND (history.signing_key_id,history.signing_key_version)=(p.signing_key_id,p.signing_key_version)
            JOIN wormhole_data.user_enrollments e ON e.user_id=p.account_id
            JOIN wormhole_data.user_key_states state ON state.user_id=p.account_id AND state.state_sequence>p.state_sequence
            JOIN wormhole_data.keys enc ON (enc.key_id,enc.key_version)=(e.encryption_key_id,e.encryption_key_version)
            JOIN wormhole_data.keys sign ON (sign.key_id,sign.key_version)=(e.signing_key_id,e.signing_key_version)
            JOIN wormhole_data.boundary_manifests m ON m.boundary_id=b.id
            CROSS JOIN LATERAL (VALUES (convert_from(m.body,'UTF8')::jsonb->'view','boundary-view'),
                                       (convert_from(m.body,'UTF8')::jsonb->'secret','boundary-secret')) d(root,kind)
            JOIN wormhole_data.keys current_key ON (current_key.key_id,current_key.key_version)=
                ((d.root#>>'{key,id}')::uuid,(d.root#>>'{key,version}')::integer)
            JOIN wormhole_data.key_copies c ON (c.key_id,c.key_version)=(current_key.key_id,current_key.key_version)
                AND (c.holder_key_id,c.holder_key_version)=(e.encryption_key_id,e.encryption_key_version)
            WHERE p.account_id=p_account AND e.encryption_key_id<>p.encryption_key_id AND e.signing_key_id<>p.signing_key_id
                AND convert_from(state.signed_state,'UTF8')::jsonb->>'active'='true'
                AND enc.kind='user-enc' AND enc.owner_id=p_account AND enc.status='active'
                AND sign.kind='user-sign' AND sign.owner_id=p_account AND sign.status='active'
                AND current_key.owner_id=b.id AND current_key.kind=d.kind AND current_key.status='active'
                AND (c.issuer_key_id,c.issuer_key_version)=(m.signer_key_id,m.signer_key_version)
                AND c.suite=2 AND octet_length(c.enc)=32 AND octet_length(c.ciphertext)=48)
    )
$restore_access$;

REVOKE ALL ON TABLE wormhole_data.account_suspension_enrollments
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.capture_suspension_enrollment(uuid),wormhole_data.suspension_enrollments_recoverable()
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

{{SUSPENSION_ENROLLMENT_EXPORT_DEFINITION}}
{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}

UPDATE wormhole_data.workspace_meta SET schema_version=77 WHERE singleton;
COMMIT;
