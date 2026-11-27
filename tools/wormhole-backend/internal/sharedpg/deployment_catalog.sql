-- The caller pins search_path to pg_catalog. Only read PostgreSQL catalogs.
WITH namespaces AS (
    SELECT oid,nspname,nspowner,nspacl FROM pg_namespace
    WHERE nspname IN ('wormhole_data','wormhole_api_v1')
), workspace_roles AS (
    SELECT r.oid,'workspace:'||suffix AS name FROM
        unnest(ARRAY['owner','observer','user','admin','enroll','deployer']) suffix
        JOIN pg_roles r ON r.rolname='wh_'||$1::text||'_'||suffix
), installers AS (
    -- A delegated creator keeps its narrow inspection grants even when
    -- another DBA reconnects. PostgreSQL records its own ADMIN membership
    -- on the newly created workspace owner role.
    SELECT DISTINCT m.member FROM pg_auth_members m
    JOIN workspace_roles o ON o.oid=m.roleid AND o.name='workspace:owner'
    JOIN namespaces n ON n.nspname='wormhole_data'
    CROSS JOIN LATERAL aclexplode(n.nspacl) a
    WHERE m.admin_option AND a.grantee=m.member AND a.privilege_type='USAGE'
      AND NOT EXISTS(SELECT FROM workspace_roles w WHERE w.oid=m.member)
), roles AS (
    SELECT r.oid,COALESCE(w.name,
        CASE WHEN r.oid=(SELECT min(member::bigint)::oid FROM installers HAVING count(*)=1)
            THEN 'installer' ELSE 'external:'||r.rolname END) AS name
    FROM pg_roles r LEFT JOIN workspace_roles w USING(oid)
    UNION ALL SELECT 0::oid,'public'
), routines AS (
    SELECT p.oid,p.proowner,p.proacl,p.prokind,n.nspname,p.proname,
        pg_get_function_arguments(p.oid) AS arguments,pg_get_function_result(p.oid) AS result,
        l.lanname,p.prosecdef,p.proconfig,p.proisstrict,p.provolatile,p.proparallel,p.proleakproof,
        p.proretset,p.probin,p.prosupport::text AS support,
        CASE WHEN p.prosqlbody IS NULL THEN $2::jsonb ->> encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')
            ELSE 'sql:'||encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex') END AS body
    FROM pg_proc p JOIN namespaces n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
), relations AS (
    SELECT c.oid,c.relowner,c.relacl,c.relkind,c.relrowsecurity,c.relforcerowsecurity,n.nspname,c.relname,
        c.relispartition AND c.relname ~ '^audit_log_[0-9]{4}(0[1-9]|1[0-2])$' AND EXISTS(
            SELECT FROM pg_inherits i JOIN pg_class parent ON parent.oid=i.inhparent
            WHERE i.inhrelid=c.oid AND parent.relnamespace=c.relnamespace AND parent.relname='audit_log'
        ) AS monthly_audit
    FROM pg_class c JOIN namespaces n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p','v','m','f','S')
), policies AS (
    SELECT p.polrelid,jsonb_agg(jsonb_build_array(p.polname,p.polcmd,p.polpermissive,role.name,
        CASE WHEN pg_get_expr(p.polqual,p.polrelid)=format('(CURRENT_USER = %L::name)',r.rolname)
            THEN 'current-role' ELSE pg_get_expr(p.polqual,p.polrelid) END,pg_get_expr(p.polwithcheck,p.polrelid))
        ORDER BY p.polname COLLATE "C",role.name COLLATE "C") AS entries
    FROM pg_policy p JOIN relations rel ON rel.oid=p.polrelid
    CROSS JOIN LATERAL unnest(p.polroles) recipient
    JOIN roles role ON role.oid=recipient LEFT JOIN pg_roles r ON r.oid=recipient
    GROUP BY p.polrelid
), objects(kind,id,owner,acltype,acl,description) AS (
    SELECT 'schema',oid,nspowner,'n'::"char",nspacl,jsonb_build_array(nspname) FROM namespaces
    UNION ALL
    SELECT 'routine',oid,proowner,'f',proacl,
        jsonb_build_array(nspname,proname,arguments,result,prokind,lanname,prosecdef,proconfig,
            proisstrict,provolatile,proparallel,proleakproof,proretset,probin,support,body)
    FROM routines
    UNION ALL
    SELECT 'relation',oid,relowner,CASE WHEN relkind='S' THEN 's' ELSE 'r' END::"char",relacl,
        jsonb_build_array(nspname,monthly_audit,CASE WHEN monthly_audit THEN '' ELSE relname END,relkind,
            relrowsecurity,relforcerowsecurity,policies.entries)
    FROM relations LEFT JOIN policies ON polrelid=oid
), grants AS (
    -- Store the difference from PostgreSQL's defaults. This preserves owner
    -- revocations while accommodating privileges introduced by a server version.
    SELECT o.kind,o.id,NULL::name AS column_name,a.*,1 AS delta
    FROM objects o CROSS JOIN LATERAL aclexplode(coalesce(o.acl,acldefault(o.acltype,o.owner))) a
    UNION ALL
    SELECT o.kind,o.id,NULL::name,a.*,-1
    FROM objects o CROSS JOIN LATERAL aclexplode(acldefault(o.acltype,o.owner)) a
    UNION ALL
    SELECT 'relation',r.oid,c.attname,a.*,1 FROM relations r JOIN pg_attribute c ON c.attrelid=r.oid
    CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE c.attnum>0 AND NOT c.attisdropped
), changes AS (
    SELECT kind,id,jsonb_build_array(column_name,issuer.name,recipient.name,privilege_type,
        is_grantable,sum(delta))::text AS entry
    FROM grants g JOIN roles issuer ON issuer.oid=g.grantor JOIN roles recipient ON recipient.oid=g.grantee
    GROUP BY kind,id,column_name,issuer.name,recipient.name,privilege_type,is_grantable HAVING sum(delta)<>0
), permissions AS (
    SELECT kind,id,jsonb_agg(entry ORDER BY entry COLLATE "C") AS entries FROM changes GROUP BY kind,id
), records AS (
    SELECT DISTINCT jsonb_build_array(o.kind,o.description,owner_role.name,p.entries)::text COLLATE "C" AS row_data
    FROM objects o JOIN roles owner_role ON owner_role.oid=o.owner LEFT JOIN permissions p USING(kind,id)
)
SELECT encode(sha256(convert_to(string_agg(row_data,E'\n' ORDER BY row_data),'UTF8')),'base64'),
    (SELECT count(*) FROM routines WHERE body IS NULL)::text FROM records
