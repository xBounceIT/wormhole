CREATE FUNCTION wormhole_data.{{GROUP_ROSTER_NAME}}(p_group uuid{{GROUP_ROSTER_OMIT_ARG}})
RETURNS TABLE(status text,body bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $roster$
DECLARE expected integer; matched integer; snapshot jsonb;
BEGIN
    SELECT count(*) INTO expected FROM (
        SELECT 1 FROM wormhole_data.group_members m JOIN wormhole_data.users u ON u.id=m.user_id
        WHERE m.group_id=p_group{{GROUP_ROSTER_OMIT_FILTER}} AND NOT u.disabled LIMIT 65
    ) members;
    IF expected=0 THEN status:='no-members'; RETURN NEXT; RETURN; END IF;
    IF expected>64 THEN status:='too-large'; RETURN NEXT; RETURN; END IF;
    SELECT count(*),jsonb_agg(jsonb_build_array(x.user_id,x.holder,x.version::text,
        encode(x.signed_state,'hex'),encode(x.certificate,'hex')) ORDER BY x.user_id) INTO matched,snapshot
    FROM (
        SELECT m.user_id,e.encryption_key_id AS holder,e.encryption_key_version AS version,s.signed_state,e.certificate
        FROM wormhole_data.group_members m JOIN wormhole_data.users u ON u.id=m.user_id
        JOIN wormhole_data.user_enrollments e ON e.user_id=m.user_id
        JOIN wormhole_data.user_key_states s ON s.user_id=m.user_id
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.encryption_key_id,e.encryption_key_version)
        WHERE m.group_id=p_group{{GROUP_ROSTER_OMIT_FILTER}} AND NOT u.disabled AND k.kind='user-enc' AND k.owner_id=m.user_id AND k.status='active'
            AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true'
        FOR SHARE OF m,u,e,s,k NOWAIT
    ) x;
    IF matched<>expected THEN status:='incomplete'; RETURN NEXT; RETURN; END IF;
    IF octet_length(snapshot::text)>3145728 THEN status:='too-large'; RETURN NEXT; RETURN; END IF;
    status:='ready';
    body:=convert_to(snapshot::text,'UTF8');
    RETURN NEXT;
END
$roster$;
