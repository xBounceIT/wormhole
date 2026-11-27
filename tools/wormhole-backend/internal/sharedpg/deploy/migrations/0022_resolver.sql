-- Version 22: private metadata-only resolver, version 1.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>21 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;


CREATE FUNCTION wormhole_data.resolver_text(p_text text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $trim$
 SELECT COALESCE(pg_catalog.btrim(p_text,E' \t\n\r\f'||chr(11)||chr(133)||chr(160)||chr(5760)||
 chr(8192)||chr(8193)||chr(8194)||chr(8195)||chr(8196)||chr(8197)||chr(8198)||chr(8199)||
 chr(8200)||chr(8201)||chr(8202)||chr(8232)||chr(8233)||chr(8239)||chr(8287)||chr(12288)),'')
$trim$;
CREATE FUNCTION wormhole_data.resolver_id(p_text text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $id$
 SELECT COALESCE(p_text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 AND p_text<>'00000000-0000-0000-0000-000000000000',false)
$id$;
{{RESOLVER_NODE_VALID_DEFINITION}}

-- Pure metadata transformation. Its caller must authenticate the complete chain,
-- enforce Use/Reveal and commit audit; this function is not a release capability.
CREATE FUNCTION wormhole_data.resolve_chain(p_chain jsonb,p_override text DEFAULT '') RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $resolve$
DECLARE count integer; i integer; n jsonb; seen text[]:='{}'; protocols integer[];
 inherited integer; protocol integer; port_owner integer; choice_owner integer;
 identity_boundary boolean:=false; choice_resolved boolean:=false; inline boolean;
 mode integer; selected_id text; kind text; k text; effective jsonb:='{}';
 choice jsonb:='{"kind":"none","id":"","nodeId":""}'; result jsonb; port integer:=0;
BEGIN
 IF p_chain IS NULL OR jsonb_typeof(p_chain)<>'array' OR octet_length(p_chain::text)>8388608
    OR p_override IS NULL OR (p_override<>'' AND NOT wormhole_data.resolver_id(p_override)) THEN
  RAISE EXCEPTION 'Invalid resolution chain' USING ERRCODE='WH016';
 END IF;
 count:=jsonb_array_length(p_chain);
 IF count<1 OR count>128 THEN RAISE EXCEPTION 'Invalid resolution chain' USING ERRCODE='WH016'; END IF;
 FOR i IN 0..count-1 LOOP
  n:=p_chain->i;
  IF NOT wormhole_data.resolver_node_valid(n) OR n->>'id'=ANY(seen)
     OR COALESCE((n->>'kind')::integer,0)<>(CASE WHEN i=0 THEN 1 ELSE 0 END)
     OR (i+1<count AND n->>'parentId' IS DISTINCT FROM p_chain->(i+1)->>'id')
     OR (i+1=count AND n->>'parentId' IS NOT NULL) THEN
   RAISE EXCEPTION 'Invalid resolution chain' USING ERRCODE='WH016';
  END IF;
  seen:=array_append(seen,n->>'id');
 END LOOP;
 protocols:=array_fill(NULL::integer,ARRAY[count]);
 FOR i IN REVERSE count-1..0 LOOP
  inherited:=COALESCE((p_chain->i->>'protocol')::integer,inherited);protocols[i+1]:=inherited;
 END LOOP;
 protocol:=protocols[1];
 IF protocol IS NULL THEN RAISE EXCEPTION 'Invalid resolution target' USING ERRCODE='WH017'; END IF;
 inline:=COALESCE((p_chain->0->>'useInlinePassword')::boolean,false);
 IF inline AND protocol NOT IN (0,1,7) THEN RAISE EXCEPTION 'Invalid resolution credential' USING ERRCODE='WH018'; END IF;
 FOR i IN 0..count-1 LOOP
  n:=p_chain->i;
  FOREACH k IN ARRAY ARRAY['host','sshKnownHostFingerprint','httpPath','tunnelEnabled','tunnelConfigId','sshAutoSudo','rdpGatewayUsageMethod','rdpGatewayHostname','rdpGatewayCredentialId','rdpGatewayUseSameCreds','rdpUseExternalClient'] LOOP
   IF effective->>k IS NULL AND n->>k IS NOT NULL THEN effective:=jsonb_set(effective,ARRAY[k],n->k); END IF;
  END LOOP;
  IF port_owner IS NULL AND n->>'port' IS NOT NULL THEN port:=(n->>'port')::integer;port_owner:=i+1; END IF;
  IF NOT identity_boundary THEN
   FOREACH k IN ARRAY ARRAY['username','rdpDomain'] LOOP
    IF effective->>k IS NULL AND n->>k IS NOT NULL THEN effective:=jsonb_set(effective,ARRAY[k],n->k); END IF;
   END LOOP;
  END IF;
  IF choice_resolved THEN CONTINUE; END IF;
  IF i=0 AND inline THEN
   choice:=jsonb_build_object('kind','inline','id',n->>'id','nodeId',n->>'id');
   choice_resolved:=true;identity_boundary:=true;CONTINUE;
  END IF;
  mode:=COALESCE((n->>'credentialMode')::integer,CASE WHEN n->>'credentialId' IS NULL THEN 0 ELSE 2 END);
  IF mode=1 THEN choice_resolved:=true;
  ELSIF mode IN (2,3) THEN
   kind:=CASE WHEN mode=2 THEN 'saved' ELSE 'slot' END;
   selected_id:=CASE WHEN mode=2 THEN n->>'credentialId' ELSE n->>'credentialSlotId' END;
   IF selected_id IS NULL THEN RAISE EXCEPTION 'Invalid resolution credential' USING ERRCODE='WH018'; END IF;
   choice:=jsonb_build_object('kind',kind,'id',selected_id,'nodeId',n->>'id');
   choice_owner:=i+1;choice_resolved:=true;identity_boundary:=true;
  END IF;
 END LOOP;
 IF wormhole_data.resolver_text(effective->>'host')='' THEN RAISE EXCEPTION 'Invalid resolution target' USING ERRCODE='WH017'; END IF;
 IF port_owner IS NOT NULL AND protocols[port_owner] IS NOT NULL AND
    (CASE WHEN protocols[port_owner]=7 THEN 0 ELSE protocols[port_owner] END) <> (CASE WHEN protocol=7 THEN 0 ELSE protocol END) THEN port:=0; END IF;
 IF port=0 THEN port:=CASE protocol WHEN 0 THEN 22 WHEN 7 THEN 22 WHEN 1 THEN 3389 WHEN 3 THEN 80 WHEN 4 THEN 443 WHEN 6 THEN 5900 ELSE 0 END; END IF;
 IF choice_owner IS NOT NULL AND protocols[choice_owner] IS NOT NULL AND
    (CASE WHEN protocols[choice_owner]=7 THEN 0 ELSE protocols[choice_owner] END) <> (CASE WHEN protocol=7 THEN 0 ELSE protocol END) THEN
  choice:='{"kind":"none","id":"","nodeId":""}';
 END IF;
 IF p_override<>'' THEN
  IF protocol NOT IN (0,1,6,7) THEN RAISE EXCEPTION 'Invalid resolution credential' USING ERRCODE='WH018'; END IF;
  choice:=jsonb_build_object('kind','override','id',p_override,'nodeId',p_chain->0->>'id');
  effective:=effective||'{"username":"","rdpDomain":""}'::jsonb;
 END IF;
 IF protocol NOT IN (0,1,6,7) THEN
  choice:='{"kind":"none","id":"","nodeId":""}';effective:=effective||'{"username":"","rdpDomain":""}'::jsonb;
 END IF;
 result:=jsonb_build_object('resolverVersion',1,'nodeId',p_chain->0->>'id','protocol',protocol,
 'host',wormhole_data.resolver_text(effective->>'host'),'port',CASE WHEN protocol=5 THEN 0 ELSE port END,
 'username',wormhole_data.resolver_text(effective->>'username'),'domain',wormhole_data.resolver_text(effective->>'rdpDomain'),
 'credential',choice,'tunnelId','','hostKeyFingerprint','','httpPath','','ignoreCertificateErrors',false,
 'sshAutoSudo',false,'gatewayMethod',0,'gatewayHost','','gatewaySameCredentials',false,'gatewayCredentialId','','externalRdpClient',false);
 IF COALESCE((effective->>'tunnelEnabled')::boolean,false) THEN
  IF protocol=5 OR wormhole_data.resolver_text(effective->>'tunnelConfigId')='' THEN RAISE EXCEPTION 'Invalid resolution tunnel' USING ERRCODE='WH019'; END IF;
  result:=result||jsonb_build_object('tunnelId',wormhole_data.resolver_text(effective->>'tunnelConfigId'));
 END IF;
 IF protocol IN (0,7) THEN result:=result||jsonb_build_object('hostKeyFingerprint',wormhole_data.resolver_text(effective->>'sshKnownHostFingerprint'),'sshAutoSudo',COALESCE((effective->>'sshAutoSudo')::boolean,false)); END IF;
 IF protocol IN (3,4) THEN result:=result||jsonb_build_object('httpPath',wormhole_data.resolver_text(effective->>'httpPath')); END IF;
 IF protocol=4 THEN result:=result||jsonb_build_object('ignoreCertificateErrors',COALESCE((p_chain->0->>'httpIgnoreCertErrors')::boolean,false)); END IF;
 IF protocol=1 THEN
  mode:=COALESCE((effective->>'rdpGatewayUsageMethod')::integer,0);
  result:=result||jsonb_build_object('gatewayMethod',mode,'externalRdpClient',COALESCE((effective->>'rdpUseExternalClient')::boolean,false));
  IF mode<>0 THEN
   IF mode=1 AND wormhole_data.resolver_text(effective->>'rdpGatewayHostname')='' THEN RAISE EXCEPTION 'Invalid resolution target' USING ERRCODE='WH017'; END IF;
   result:=result||jsonb_build_object('gatewayHost',wormhole_data.resolver_text(effective->>'rdpGatewayHostname'),'gatewaySameCredentials',COALESCE((effective->>'rdpGatewayUseSameCreds')::boolean,false));
   IF NOT COALESCE((effective->>'rdpGatewayUseSameCreds')::boolean,false) THEN result:=result||jsonb_build_object('gatewayCredentialId',wormhole_data.resolver_text(effective->>'rdpGatewayCredentialId')); END IF;
  END IF;
 END IF;
 RETURN result;
END
$resolve$;

CREATE FUNCTION wormhole_data.apply_credential(p_plan jsonb,p_credential jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $credential$
DECLARE family text;
BEGIN
 family:=CASE (p_plan->>'protocol')::integer WHEN 0 THEN 'ssh' WHEN 7 THEN 'ssh' WHEN 1 THEN 'rdp' WHEN 6 THEN 'vnc' ELSE '' END;
 IF p_plan IS NULL OR p_credential IS NULL OR COALESCE(p_plan->'credential'->>'kind','') NOT IN ('saved','override')
    OR p_plan->'credential'->>'id' IS DISTINCT FROM p_credential->>'id' OR family IS DISTINCT FROM p_credential->>'protocol' THEN
  RAISE EXCEPTION 'Invalid resolution credential' USING ERRCODE='WH018';
 END IF;
 IF p_plan->>'username'='' OR p_plan->'credential'->>'kind'='override' THEN p_plan:=p_plan||jsonb_build_object('username',wormhole_data.resolver_text(p_credential->>'username')); END IF;
 IF p_plan->>'domain'='' OR p_plan->'credential'->>'kind'='override' THEN p_plan:=p_plan||jsonb_build_object('domain',wormhole_data.resolver_text(p_credential->>'domain')); END IF;
 RETURN p_plan;
END
$credential$;
REVOKE ALL ON FUNCTION wormhole_data.resolver_text(text),wormhole_data.resolver_id(text),wormhole_data.resolver_node_valid(jsonb),wormhole_data.resolve_chain(jsonb,text),wormhole_data.apply_credential(jsonb,jsonb) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
UPDATE wormhole_data.workspace_meta SET schema_version=22 WHERE singleton;
COMMIT;
