CREATE {{REPLACE}}FUNCTION wormhole_data.maintain_audit_partitions(p_workspace uuid, p_retention_days integer DEFAULT 400)
RETURNS TABLE(partitions_created integer, partitions_dropped integer, expired_rows_deleted bigint)
LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' SET datestyle='ISO, YMD' SET lock_timeout='2s'
AS $maintain$
DECLARE
    checked_at constant timestamptz := pg_catalog.statement_timestamp();
    cutoff timestamptz;
    month_start timestamptz;
    month_end timestamptz;
    child record;
    child_name text;
BEGIN
    IF current_user<>'wh_{{TAG}}_owner' OR p_workspace IS DISTINCT FROM '{{WORKSPACE_ID}}'::uuid THEN
        RAISE EXCEPTION 'Audit maintenance requires the workspace owner and identity' USING ERRCODE='42501';
    END IF;
    IF p_retention_days IS NULL OR p_retention_days<1 THEN
        RAISE EXCEPTION 'Audit retention must be a positive number of days' USING ERRCODE='22023';
    END IF;
    cutoff := checked_at - pg_catalog.make_interval(days=>p_retention_days);
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace maintenance is already in progress' USING ERRCODE='55P03';
    END IF;
    LOCK TABLE ONLY wormhole_data.audit_log IN SHARE UPDATE EXCLUSIVE MODE NOWAIT;
    partitions_created := 0;
    partitions_dropped := 0;
    FOR child IN
        SELECT c.relname, n.nspname, c.relkind, pg_catalog.pg_get_expr(c.relpartbound,c.oid) AS bounds
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid=i.inhrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE i.inhparent='wormhole_data.audit_log'::regclass
        ORDER BY c.relname
    LOOP
        IF child.nspname<>'wormhole_data' OR child.relkind<>'r'
           OR child.relname !~ '^audit_log_[0-9]{4}(0[1-9]|1[0-2])$' THEN
            RAISE EXCEPTION 'Unexpected audit partition' USING ERRCODE='55000';
        END IF;
        month_start := pg_catalog.to_date(pg_catalog.right(child.relname,6),'YYYYMM')::timestamptz;
        month_end := month_start + interval '1 month';
        IF child.bounds IS DISTINCT FROM pg_catalog.format('FOR VALUES FROM (%L) TO (%L)',month_start,month_end) THEN
            RAISE EXCEPTION 'Unexpected audit partition bounds' USING ERRCODE='55000';
        END IF;
        IF month_end<=cutoff THEN
            EXECUTE pg_catalog.format('DROP TABLE wormhole_data.%I',child.relname);
            partitions_dropped := partitions_dropped + 1;
        END IF;
    END LOOP;

    FOR month_offset IN 0..2 LOOP
        month_start := pg_catalog.date_trunc('month',checked_at) + pg_catalog.make_interval(months=>month_offset);
        month_end := month_start + interval '1 month';
        child_name := 'audit_log_' || pg_catalog.to_char(month_start,'YYYYMM');
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_inherits i
                       WHERE i.inhparent='wormhole_data.audit_log'::regclass
                         AND i.inhrelid=pg_catalog.to_regclass(pg_catalog.format('wormhole_data.%I',child_name))) THEN
            EXECUTE pg_catalog.format(
                'CREATE TABLE wormhole_data.%I PARTITION OF wormhole_data.audit_log FOR VALUES FROM (%L) TO (%L)',
                child_name,month_start,month_end);
{{NEW_PARTITION_POLICY}}            partitions_created := partitions_created + 1;
        END IF;
    END LOOP;
    DELETE FROM wormhole_data.audit_log WHERE at<cutoff;
    GET DIAGNOSTICS expired_rows_deleted = ROW_COUNT;
    RETURN NEXT;
END
$maintain$;
