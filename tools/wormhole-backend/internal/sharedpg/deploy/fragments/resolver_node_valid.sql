CREATE FUNCTION wormhole_data.resolver_node_valid(n jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $valid$
DECLARE entry record; value text; number numeric;
 types constant jsonb := '{
  "id": "string",
  "parentId": "string",
  "ownerUserId": "string",
  "name": "string",
  "kind": "number",
  "sortOrder": "number",
  "protocol": "number",
  "host": "string",
  "port": "number",
  "httpPath": "string",
  "username": "string",
  "credentialId": "string",
  "credentialMode": "number",
  "credentialSlotId": "string",
  "useInlinePassword": "boolean",
  "sshAutoSudo": "boolean",
  "httpIgnoreCertErrors": "boolean",
  "tunnelEnabled": "boolean",
  "tunnelConfigId": "string",
  "serialBaudRate": "number",
  "serialDataBits": "number",
  "serialStopBits": "number",
  "serialParity": "number",
  "serialFlowControl": "number",
  "sshKeyFileName": "string",
  "sshKnownHostFingerprint": "string",
  "rdpDomain": "string",
  "rdpScreenSize": "string",
  "rdpFullScreen": "boolean",
  "rdpColorDepth": "number",
  "rdpUseAllMonitors": "boolean",
  "rdpAudioMode": "number",
  "rdpAudioCaptureMode": "number",
  "rdpKeyboardHookMode": "number",
  "rdpRedirectClipboard": "boolean",
  "rdpRedirectPrinters": "boolean",
  "rdpRedirectSmartCards": "boolean",
  "rdpRedirectPorts": "boolean",
  "rdpRedirectDevices": "boolean",
  "rdpRedirectDrives": "string",
  "rdpConnectionSpeed": "number",
  "rdpDesktopBackground": "boolean",
  "rdpFontSmoothing": "boolean",
  "rdpDesktopComposition": "boolean",
  "rdpWindowDrag": "boolean",
  "rdpMenuAnimation": "boolean",
  "rdpVisualStyles": "boolean",
  "rdpBitmapCaching": "boolean",
  "rdpAutoReconnect": "boolean",
  "rdpServerAuthentication": "number",
  "rdpGatewayUsageMethod": "number",
  "rdpGatewayHostname": "string",
  "rdpGatewayCredentialId": "string",
  "rdpGatewayBypassLocal": "boolean",
  "rdpGatewayUseSameCreds": "boolean",
  "rdpUseExternalClient": "boolean"
}';
 limits constant jsonb := '{
  "name": 1024,
  "host": 16384,
  "httpPath": 16384,
  "username": 2048,
  "rdpDomain": 2048,
  "rdpScreenSize": 128,
  "rdpRedirectDrives": 512,
  "rdpGatewayHostname": 4096,
  "sshKeyFileName": 1024,
  "sshKnownHostFingerprint": 128
}';
 ranges constant jsonb := '{
  "port": [
    0,
    65535
  ],
  "credentialMode": [
    0,
    3
  ],
  "serialBaudRate": [
    1,
    2147483647
  ],
  "serialDataBits": [
    5,
    8
  ],
  "serialStopBits": [
    1,
    3
  ],
  "serialParity": [
    0,
    4
  ],
  "serialFlowControl": [
    0,
    3
  ],
  "rdpAudioMode": [
    0,
    2
  ],
  "rdpAudioCaptureMode": [
    0,
    1
  ],
  "rdpKeyboardHookMode": [
    0,
    2
  ],
  "rdpConnectionSpeed": [
    1,
    7
  ],
  "rdpServerAuthentication": [
    0,
    2
  ],
  "rdpGatewayUsageMethod": [
    0,
    3
  ]
}';
BEGIN
 IF n IS NULL OR jsonb_typeof(n)<>'object' THEN RETURN false; END IF;
{{IMPORT_RESOLVER_NODE_VALIDATION}} FOR entry IN SELECT * FROM jsonb_each(n) LOOP
  IF NOT types ? entry.key THEN RETURN false; END IF;
  IF entry.value='null'::jsonb THEN CONTINUE; END IF;
  IF jsonb_typeof(entry.value)<>types->>entry.key THEN RETURN false; END IF;
  value:=n->>entry.key;
  IF types->>entry.key='number' THEN
   IF value !~ '^-?(0|[1-9][0-9]*)$' THEN RETURN false; END IF;
   number:=value::numeric;
   IF number < -9223372036854775808 OR number > 9223372036854775807 THEN RETURN false; END IF;
   IF ranges ? entry.key AND (number<(ranges->entry.key->>0)::numeric OR number>(ranges->entry.key->>1)::numeric) THEN RETURN false; END IF;
  END IF;
  IF limits ? entry.key AND octet_length(value)>(limits->>entry.key)::integer THEN RETURN false; END IF;
 END LOOP;
 IF NOT wormhole_data.resolver_id(n->>'id') OR n->>'parentId'=n->>'id'
    OR wormhole_data.resolver_text(n->>'name')='' OR length(n->>'name')>256
    OR (n->>'name') ~ U&'[\0001-\001f\007f-\009f]' OR COALESCE((n->>'kind')::integer,0) NOT IN (0,1) THEN RETURN false; END IF;
 FOREACH value IN ARRAY ARRAY['parentId','ownerUserId','credentialId','credentialSlotId','tunnelConfigId','rdpGatewayCredentialId'] LOOP
  IF n->>value IS NOT NULL AND NOT wormhole_data.resolver_id(n->>value) THEN RETURN false; END IF;
 END LOOP;
 IF n->>'protocol' IS NOT NULL AND (n->>'protocol')::numeric NOT IN (0,1,3,4,5,6,7) THEN RETURN false; END IF;
 IF n->>'rdpColorDepth' IS NOT NULL AND (n->>'rdpColorDepth')::numeric NOT IN (15,16,24,32) THEN RETURN false; END IF;
 IF (n->>'credentialMode')::integer=2 AND n->>'credentialId' IS NULL THEN RETURN false; END IF;
 IF (n->>'credentialMode')::integer=3 THEN
  IF n->>'credentialSlotId' IS NULL OR n->>'credentialId' IS NOT NULL THEN RETURN false; END IF;
 ELSIF n->>'credentialSlotId' IS NOT NULL THEN RETURN false;
 END IF;
 FOREACH value IN ARRAY ARRAY['host','username','rdpDomain','rdpGatewayHostname'] LOOP
  IF position(chr(13) IN n->>value)>0 OR position(chr(10) IN n->>value)>0 THEN RETURN false; END IF;
 END LOOP;
 value:=n->>'sshKnownHostFingerprint';
 IF value IS NOT NULL AND value<>'' THEN
  IF value !~ '^SHA256:[A-Za-z0-9+/]{43}$' OR encode(decode(substr(value,8)||'=','base64'),'base64')<>substr(value,8)||'=' THEN RETURN false; END IF;
 END IF;
 IF COALESCE((n->>'useInlinePassword')::boolean,false) AND
    (COALESCE((n->>'kind')::integer,0)<>1 OR (n->>'protocol' IS NOT NULL AND (n->>'protocol')::numeric NOT IN (0,1,7))) THEN RETURN false; END IF;
 IF (n->>'kind')::integer=1 AND (n->>'protocol')::numeric=5 AND
    (n->>'credentialId' IS NOT NULL OR n->>'credentialSlotId' IS NOT NULL OR n->>'tunnelConfigId' IS NOT NULL OR COALESCE((n->>'tunnelEnabled')::boolean,false)) THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END
$valid$;
