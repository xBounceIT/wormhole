-- RFC 8032 section 5.1.7. PostgreSQL 16 provides SHA-512 and exact integer
-- arithmetic without extensions. These routines verify public record seals only.
CREATE FUNCTION wormhole_data.ed_le(p_bytes bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $le$
DECLARE n numeric:=0; i integer;
BEGIN
    FOR i IN REVERSE octet_length(p_bytes)-1..0 LOOP n:=n*256+get_byte(p_bytes,i); END LOOP;
    RETURN n;
END
$le$;

CREATE FUNCTION wormhole_data.ed_pow(p_base numeric,p_exponent numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $pow$
DECLARE prime constant numeric:=57896044618658097711785492504343953926634992332820282019728792003956564819949;
    base numeric:=mod(p_base,prime); exponent numeric:=p_exponent; result numeric:=1;
BEGIN
    WHILE exponent>0 LOOP
        IF mod(exponent,2)=1 THEN result:=mod(result*base,prime); END IF;
        base:=mod(base*base,prime); exponent:=div(exponent,2);
    END LOOP;
    RETURN result;
END
$pow$;

-- Extended homogeneous coordinates (X,Y,Z,T).
CREATE FUNCTION wormhole_data.ed_decode(p_point bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $decode$
DECLARE prime constant numeric:=57896044618658097711785492504343953926634992332820282019728792003956564819949;
    d constant numeric:=37095705934669439343138083508754565189542113879843219016388785533085940283555;
    sqrt_m1 constant numeric:=19681161376707505956807079304988542015446066515923890162744021073123829784752;
    y numeric; x numeric; y2 numeric; u numeric; v numeric; v3 numeric; check_x numeric; sign_bit integer;
BEGIN
    IF octet_length(p_point)<>32 THEN RETURN NULL; END IF;
    sign_bit:=get_byte(p_point,31)>>7;
    y:=wormhole_data.ed_le(set_byte(p_point,31,get_byte(p_point,31)&127));
    IF y>=prime THEN RETURN NULL; END IF;
    y2:=mod(y*y,prime); u:=mod(y2-1+prime,prime); v:=mod(d*y2+1,prime);
    v3:=mod(v*v*v,prime);
    x:=mod(u*v3*wormhole_data.ed_pow(u*v3*v3*v,div(prime-5,8)),prime);
    check_x:=mod(v*x*x,prime);
    IF check_x<>u THEN
        IF mod(check_x+u,prime)<>0 THEN RETURN NULL; END IF;
        x:=mod(x*sqrt_m1,prime);
    END IF;
    IF x=0 AND sign_bit=1 THEN RETURN NULL; END IF;
    IF mod(x,2)<>sign_bit THEN x:=prime-x; END IF;
    RETURN ARRAY[x,y,1::numeric,mod(x*y,prime)];
END
$decode$;

CREATE FUNCTION wormhole_data.ed_add(p numeric[],q numeric[]) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $add$
DECLARE prime constant numeric:=57896044618658097711785492504343953926634992332820282019728792003956564819949;
    d constant numeric:=37095705934669439343138083508754565189542113879843219016388785533085940283555;
    a numeric:=mod((p[2]-p[1])*(q[2]-q[1]),prime); b numeric:=mod((p[2]+p[1])*(q[2]+q[1]),prime);
    c numeric:=mod(2*d*p[4]*q[4],prime); z numeric:=mod(2*p[3]*q[3],prime);
BEGIN
    RETURN ARRAY[mod((b-a)*(z-c),prime),mod((z+c)*(b+a),prime),mod((z-c)*(z+c),prime),mod((b-a)*(b+a),prime)];
END
$add$;

CREATE FUNCTION wormhole_data.ed_scale(p numeric[],n numeric) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $scale$
DECLARE point numeric[]:=p; result numeric[]:=ARRAY[0,1,1,0]::numeric[]; k numeric:=n;
BEGIN
    WHILE k>0 LOOP
        IF mod(k,2)=1 THEN result:=wormhole_data.ed_add(result,point); END IF;
        point:=wormhole_data.ed_add(point,point); k:=div(k,2);
    END LOOP;
    RETURN result;
END
$scale$;

CREATE FUNCTION wormhole_data.ed25519_verify(p_key bytea,p_message bytea,p_signature bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $verify$
DECLARE prime constant numeric:=57896044618658097711785492504343953926634992332820282019728792003956564819949;
    subgroup constant numeric:=7237005577332262213973186563042994240857116359379907606001950938285454250989;
    base numeric[]; pub numeric[]; r numeric[]; left_point numeric[]; right_point numeric[]; s numeric; k numeric;
BEGIN
    IF octet_length(p_key) IS DISTINCT FROM 32 OR octet_length(p_signature) IS DISTINCT FROM 64
        OR p_message IS NULL OR octet_length(p_message)>1048576 THEN RETURN false; END IF;
    s:=wormhole_data.ed_le(substr(p_signature,33));
    IF s>=subgroup THEN RETURN false; END IF;
    pub:=wormhole_data.ed_decode(p_key); r:=wormhole_data.ed_decode(substr(p_signature,1,32));
    IF pub IS NULL OR r IS NULL OR (pub[1]=0 AND pub[2]=1) THEN RETURN false; END IF;
    right_point:=wormhole_data.ed_scale(pub,subgroup);
    IF mod(right_point[1],prime)<>0 OR mod(right_point[2]-right_point[3],prime)<>0 THEN RETURN false; END IF;
    base:=wormhole_data.ed_decode(decode('58'||repeat('66',31),'hex'));
    k:=mod(wormhole_data.ed_le(sha512(substr(p_signature,1,32)||p_key||p_message)),subgroup);
    left_point:=wormhole_data.ed_scale(base,s);
    right_point:=wormhole_data.ed_add(r,wormhole_data.ed_scale(pub,k));
    RETURN mod(left_point[1]*right_point[3]-right_point[1]*left_point[3],prime)=0
       AND mod(left_point[2]*right_point[3]-right_point[2]*left_point[3],prime)=0;
END
$verify$;
REVOKE ALL ON FUNCTION wormhole_data.ed_le(bytea),wormhole_data.ed_pow(numeric,numeric),wormhole_data.ed_decode(bytea),
    wormhole_data.ed_add(numeric[],numeric[]),wormhole_data.ed_scale(numeric[],numeric),wormhole_data.ed25519_verify(bytea,bytea,bytea) FROM PUBLIC;
