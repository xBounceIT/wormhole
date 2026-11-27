-- Version 91: optional row security for direct access to workspace tables.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>90 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Called by owner-only maintenance. Policies add no SQL privileges. The
-- observer retains its column grants and the delegated installer its probe.
CREATE FUNCTION wormhole_data.configure_relation_rls(p_relation regclass,p_enabled boolean) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $relation$
DECLARE tab record; policy record; installer name; expected_role name; expected_policies integer := 1;
    found_policies integer := 0; statement text;
BEGIN
    IF current_user<>'wh_{{TAG}}_owner' OR p_enabled IS NULL THEN
        RAISE EXCEPTION 'Row security requires the workspace owner' USING ERRCODE='42501';
    END IF;
    EXECUTE format('LOCK TABLE ONLY %s IN ACCESS EXCLUSIVE MODE NOWAIT',p_relation);
    SELECT c.relname,c.relowner,c.relrowsecurity,c.relforcerowsecurity INTO STRICT tab
    FROM pg_class c WHERE c.oid=p_relation AND c.relnamespace='wormhole_data'::regnamespace AND c.relkind IN ('r','p');
    IF tab.relowner<>current_user::regrole OR tab.relrowsecurity<>tab.relforcerowsecurity THEN
        RAISE EXCEPTION 'Unexpected workspace row security configuration' USING ERRCODE='55000';
    END IF;
    IF tab.relname IN ('devices','device_confirmations') THEN
        expected_policies := 2;
    ELSIF tab.relname='workspace_meta' THEN
        -- Only the original delegated DBA holds the reconciliation columns and
        -- ADMIN OPTION on the owner without SET or INHERIT.
        installer := (SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
            WHERE m.roleid=tab.relowner AND m.admin_option AND NOT m.set_option AND NOT m.inherit_option
              AND (SELECT count(DISTINCT c.attname) FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a
                   WHERE c.attrelid=p_relation AND c.attname IN ('singleton','workspace_id','role_tag','schema_version','state','require_tls')
                     AND a.grantee=m.member AND a.grantor=tab.relowner AND a.privilege_type='SELECT')=6);
        IF installer IS NOT NULL THEN expected_policies := 2; END IF;
    END IF;
    FOR policy IN SELECT p.*,pg_get_expr(p.polqual,p.polrelid) AS predicate FROM pg_policy p WHERE p.polrelid=p_relation LOOP
        expected_role := CASE
            WHEN policy.polname='wh_owner' AND policy.polcmd='*' THEN current_user
            WHEN policy.polname='wh_observer' AND policy.polcmd='r' AND tab.relname IN ('devices','device_confirmations') THEN 'wh_{{TAG}}_observer'
            WHEN policy.polname='wh_installer' AND policy.polcmd='r' THEN installer
        END;
        IF NOT tab.relrowsecurity OR expected_role IS NULL OR NOT policy.polpermissive
           OR policy.polroles<>ARRAY[quote_ident(expected_role)::regrole::oid] OR policy.polwithcheck IS NOT NULL
           OR policy.predicate IS DISTINCT FROM format('(CURRENT_USER = %L::name)',expected_role) THEN
            RAISE EXCEPTION 'Existing row policy requires DBA review' USING ERRCODE='55000';
        END IF;
        found_policies := found_policies+1;
        IF NOT p_enabled THEN EXECUTE format('DROP POLICY %I ON %s',policy.polname,p_relation); END IF;
    END LOOP;
    IF tab.relrowsecurity AND found_policies<>expected_policies THEN
        RAISE EXCEPTION 'Missing workspace row policy' USING ERRCODE='55000';
    END IF;
    IF tab.relrowsecurity=p_enabled THEN RETURN; END IF;
    IF p_enabled THEN
        EXECUTE format('CREATE POLICY wh_owner ON %s TO wh_{{TAG}}_owner USING (current_user = %L::name)',p_relation,current_user);
        IF tab.relname IN ('devices','device_confirmations') THEN
            EXECUTE format('CREATE POLICY wh_observer ON %s FOR SELECT TO wh_{{TAG}}_observer USING (current_user = %L::name)',
                p_relation,'wh_{{TAG}}_observer');
        ELSIF installer IS NOT NULL THEN
            EXECUTE format('CREATE POLICY wh_installer ON %s FOR SELECT TO %I USING (current_user = %L::name)',p_relation,installer,installer);
        END IF;
        statement := 'ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY';
    ELSE
        statement := 'NO FORCE ROW LEVEL SECURITY, DISABLE ROW LEVEL SECURITY';
    END IF;
    EXECUTE format('ALTER TABLE ONLY wormhole_data.%I %s',tab.relname,statement);
END
$relation$;
REVOKE ALL ON FUNCTION wormhole_data.configure_relation_rls(regclass,boolean) FROM PUBLIC;

CREATE FUNCTION wormhole_data.set_row_security(p_workspace uuid,p_enabled boolean) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $configure$
DECLARE tab record;
BEGIN
    IF current_user<>'wh_{{TAG}}_owner' OR p_workspace IS DISTINCT FROM '{{WORKSPACE_ID}}'::uuid OR p_enabled IS NULL THEN
        RAISE EXCEPTION 'Row security requires the workspace owner and identity' USING ERRCODE='42501';
    END IF;
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace maintenance in progress' USING ERRCODE='55P03';
    END IF;
    FOR tab IN SELECT oid FROM pg_class WHERE relnamespace='wormhole_data'::regnamespace AND relkind IN ('r','p') ORDER BY relname LOOP
        PERFORM wormhole_data.configure_relation_rls(tab.oid,p_enabled);
    END LOOP;
END
$configure$;
REVOKE ALL ON FUNCTION wormhole_data.set_row_security(uuid,boolean) FROM PUBLIC;

{{MAINTAIN_AUDIT_PARTITIONS}}
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=91 WHERE singleton;
COMMIT;
