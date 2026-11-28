-- Preserve the canonical JSON field order and escaping of the format-1 Go
-- records. JSONB ordering and its whitespace are not signature encodings.
CREATE FUNCTION wormhole_data.node_edit_message(p_workspace uuid,p_boundary uuid,p_metadata jsonb,p_fields jsonb,
    p_signer uuid,p_version integer,p_revision bigint) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $message$
DECLARE item text; value text; parts text[]:='{}'; body text; domain text; attachment jsonb; field jsonb;
BEGIN
    IF p_fields IS NULL THEN
        FOREACH item IN ARRAY ARRAY['id','parentId','ownerUserId','name','kind','sortOrder',
        'protocol','host','port','httpPath','username','credentialId',
        'credentialMode','credentialSlotId','useInlinePassword','sshAutoSudo','httpIgnoreCertErrors','tunnelEnabled',
        'tunnelConfigId','serialBaudRate','serialDataBits','serialStopBits','serialParity','serialFlowControl',
        'sshKeyFileName','sshKnownHostFingerprint','rdpDomain','rdpScreenSize','rdpFullScreen','rdpColorDepth',
        'rdpUseAllMonitors','rdpAudioMode','rdpAudioCaptureMode','rdpKeyboardHookMode','rdpRedirectClipboard','rdpRedirectPrinters',
        'rdpRedirectSmartCards','rdpRedirectPorts','rdpRedirectDevices','rdpRedirectDrives','rdpConnectionSpeed','rdpDesktopBackground',
        'rdpFontSmoothing','rdpDesktopComposition','rdpWindowDrag','rdpMenuAnimation','rdpVisualStyles','rdpBitmapCaching',
        'rdpAutoReconnect','rdpServerAuthentication','rdpGatewayUsageMethod','rdpGatewayHostname','rdpGatewayCredentialId','rdpGatewayBypassLocal',
        'rdpGatewayUseSameCreds','rdpUseExternalClient','imported'] LOOP
            IF item='imported' THEN
                attachment:=p_metadata->'imported';
                IF attachment IS NULL THEN CONTINUE; END IF;
                value:='{"digest":'||(attachment->'digest')::text||',"retainedPins":'||(attachment->'retainedPins')::text||
                    CASE WHEN attachment ? 'noteVersion' THEN ',"noteVersion":'||(attachment->'noteVersion')::text ELSE '' END||'}';
            ELSE
                value:=(p_metadata->item)::text;
            END IF;
            IF value IS NULL THEN RETURN NULL; END IF;
            parts:=array_append(parts,'"'||item||'":'||value);
        END LOOP;
        body:='"metadata":{'||array_to_string(parts,',')||'}';
        domain:='wormhole/v1/shared-node-metadata';
    ELSE
        FOR field IN SELECT jsonb_array_elements(p_fields) LOOP
            parts:=array_append(parts,'{"field":'||(field->'field')::text||',"version":'||(field->'version')::text||
                ',"present":'||(field->'present')::text||'}');
        END LOOP;
        body:='"record":{"nodeId":'||(p_metadata->'id')::text||',"fields":['||array_to_string(parts,',')||'],"deleted":false}';
        domain:='wormhole/v1/shared-node-fields';
    END IF;
    body:=replace(replace(replace(replace(replace(body,'&',E'\\u0026'),'<',E'\\u003c'),'>',E'\\u003e'),chr(8232),E'\\u2028'),chr(8233),E'\\u2029');
    body:=format('{"workspaceId":"%s","boundaryId":"%s","suite":2,%s,"seal":{"formatVersion":1,"signerKeyId":"%s","signerKeyVersion":%s,"capabilityId":null,"revision":%s,"signature":null}}',
        p_workspace,p_boundary,body,p_signer,p_version,p_revision);
    RETURN convert_to(domain,'UTF8')||decode('00','hex')||convert_to(body,'UTF8');
END
$message$;
REVOKE ALL ON FUNCTION wormhole_data.node_edit_message(uuid,uuid,jsonb,jsonb,uuid,integer,bigint) FROM PUBLIC;
