-- Version 39: revision-bound signed node fields and audited inline release.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>38 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Node fields have their own domain-separated member signature. They share the
-- authenticated node revision and boundary; neither an unsigned value version nor
-- a standalone old field manifest may steer a current release.
CREATE FUNCTION wormhole_data.node_fields_valid(p_fields jsonb,p_deleted boolean)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $fields$
DECLARE entry jsonb; version_text text;
BEGIN
    IF jsonb_typeof(p_fields) IS DISTINCT FROM 'array' OR p_deleted IS NULL THEN RETURN false; END IF;
    IF jsonb_array_length(p_fields)>1 THEN RETURN false; END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_fields) LOOP
        IF jsonb_typeof(entry) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
        IF (SELECT count(*) FROM jsonb_object_keys(entry))<>3
           OR jsonb_typeof(entry->'field') IS DISTINCT FROM 'string' OR entry->>'field'<>'inlinePassword'
           OR jsonb_typeof(entry->'version') IS DISTINCT FROM 'number'
           OR jsonb_typeof(entry->'present') IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
        version_text:=entry->>'version';
        IF version_text !~ '^[1-9][0-9]{0,18}$' THEN RETURN false; END IF;
        IF version_text::numeric>9223372036854775807 OR (p_deleted AND (entry->>'present')::boolean) THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END
$fields$;
CREATE TABLE wormhole_data.node_secret_manifests (
    node_id uuid PRIMARY KEY REFERENCES wormhole_data.nodes(id),
    fields jsonb NOT NULL CHECK(octet_length(fields::text)<=2048),
    deleted boolean NOT NULL DEFAULT false,
    boundary_id uuid NOT NULL CHECK(boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    row_version bigint NOT NULL CHECK(row_version>=1),
    seal_suite smallint NOT NULL CHECK(seal_suite=2),
    seal_signer_key_id uuid NOT NULL,
    seal_signer_key_version integer NOT NULL,
    seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    seal bytea NOT NULL CHECK(octet_length(seal)=64),
    FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK(wormhole_data.node_fields_valid(fields,deleted))
);
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.node_secret_manifests
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
REVOKE ALL ON TABLE wormhole_data.node_secret_manifests FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_data.node_fields_valid(jsonb,boolean) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;

CREATE OR REPLACE FUNCTION wormhole_data.selection_record(p_kind text,p_subject uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,subject_id uuid,epoch bigint,change_seq bigint,
    record jsonb,boundary_id uuid,row_version bigint,seal_suite smallint,seal_signer_key_id uuid,
    seal_signer_key_version integer,seal_capability_id uuid,seal bytea,
    author_id uuid,signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $selection$
DECLARE meta record; item record; author record;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('slot','slot-value','override','node-fields')
       OR p_subject IS NULL OR p_subject='00000000-0000-0000-0000-000000000000'::uuid
       OR (p_kind IN ('slot','node-fields') AND p_user IS NOT NULL)
       OR (p_kind NOT IN ('slot','node-fields') AND (p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid))
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid selection request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013';
    END IF;
    IF p_kind='slot' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('id',s.id,'name',s.name,'protocol',s.protocol,'defaultCredentialId',COALESCE(s.default_credential_id::text,''),'allowSelfService',s.allow_self_service,'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.credential_slots s WHERE s.id=p_subject;
    ELSIF p_kind='slot-value' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('id',s.id,'slotId',s.slot_id,'userId',s.user_id,'credentialId',COALESCE(s.credential_id::text,''),'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.credential_slot_values s WHERE s.slot_id=p_subject AND s.user_id=p_user;
    ELSIF p_kind='override' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('nodeId',s.node_id,'userId',s.user_id,'credentialId',COALESCE(s.credential_id::text,''),'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.user_node_overrides s WHERE s.node_id=p_subject AND s.user_id=p_user;
    ELSIF p_kind='node-fields' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('nodeId',s.node_id,'fields',s.fields,'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.node_secret_manifests s JOIN wormhole_data.nodes n ON n.id=s.node_id
            WHERE s.node_id=p_subject AND n.kind=1 AND s.row_version=n.row_version AND s.boundary_id=n.boundary_id;
    END IF;
    IF NOT FOUND THEN
        IF p_kind='node-fields' THEN RAISE EXCEPTION 'Node field material unavailable' USING ERRCODE='WH010'; END IF;
        RAISE EXCEPTION 'Selection metadata unavailable' USING ERRCODE='WH018';
    END IF;
    IF octet_length(item.body::text)>16384 THEN RAISE EXCEPTION 'Selection projection is too large' USING ERRCODE='54000'; END IF;
    SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    -- Preserve tombstones and signed revocations for native monotonic floors.
    RETURN QUERY SELECT meta.workspace_id,p_subject,meta.epoch,meta.change_seq,item.body,
        item.boundary_id,item.row_version,item.seal_suite,item.seal_signer_key_id,item.seal_signer_key_version,item.seal_capability_id,item.seal,
        author.author_id,author.signing_key_id,author.signing_key_version,author.state_sequence,author.signed_state,
        author.suite,author.public_key,author.cert_signer_key_id,author.cert_signer_key_version,author.cert_revision,author.cert_signature;
END
$selection$;

CREATE FUNCTION wormhole_data.owner_values(p_kind text,p_owner uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,owner_id uuid,epoch bigint,change_seq bigint,
    field text,row_version bigint,dek_id uuid,dek_version integer,envelope bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $values$
DECLARE profile record; entry jsonb; value wormhole_data.secret_values; size bigint:=0;
BEGIN
    -- Validates ID/snapshot/readiness/API and locks workspace against all writers.
    IF p_kind='credential' THEN
        SELECT * INTO STRICT profile FROM wormhole_data.credential_record(p_owner,p_epoch,p_change_seq);
    ELSIF p_kind='node' THEN
        SELECT * INTO STRICT profile FROM wormhole_data.selection_record('node-fields',p_owner,NULL,p_epoch,p_change_seq);
    ELSE
        RAISE EXCEPTION 'Invalid value owner' USING ERRCODE='22023';
    END IF;
    IF (profile.record->>'deleted')::boolean THEN RAISE EXCEPTION 'Credential unavailable' USING ERRCODE='WH018'; END IF;
    FOR entry IN SELECT f.value FROM jsonb_array_elements(profile.record->'fields') f LOOP
        IF NOT (entry->>'present')::boolean THEN CONTINUE; END IF;
        SELECT v.* INTO value FROM wormhole_data.secret_values v
            WHERE v.owner_kind=p_kind AND v.owner_id=p_owner AND v.field=entry->>'field';
        IF NOT FOUND OR value.row_version<>(entry->>'version')::bigint
           OR NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=value.dek_id AND k.key_version=value.dek_version AND k.kind='dek') THEN
            RAISE EXCEPTION 'Credential value unavailable' USING ERRCODE='WH010';
        END IF;
        IF octet_length(value.envelope)>6291456 THEN RAISE EXCEPTION 'Credential value is too large' USING ERRCODE='54000'; END IF;
        size:=size+octet_length(value.envelope);
        IF size>8388608 THEN RAISE EXCEPTION 'Credential values are too large' USING ERRCODE='54000'; END IF;
        RETURN QUERY SELECT profile.workspace_id,p_owner,profile.epoch,profile.change_seq,
            value.field,value.row_version,value.dek_id,value.dek_version,value.envelope;
    END LOOP;
END
$values$;
REVOKE ALL ON FUNCTION wormhole_data.owner_values(text,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
CREATE OR REPLACE FUNCTION wormhole_data.credential_values(p_credential uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,credential_id uuid,epoch bigint,change_seq bigint,
    field text,row_version bigint,dek_id uuid,dek_version integer,envelope bytea)
LANGUAGE sql SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' AS $values$
    SELECT * FROM wormhole_data.owner_values('credential',p_credential,p_epoch,p_change_seq);
$values$;

-- Private encrypted release preparation. The public caller must derive p_user
-- from device admission, authorize node/account boundaries, and consume the
-- committed audit ticket ONLY AFTER this complete bounded payload is ready.
CREATE OR REPLACE FUNCTION wormhole_data.credential_release_graph(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $graph$
DECLARE metadata jsonb; account record; state jsonb; holder_id uuid; holder_version integer;
        role_name text; profile_row jsonb; field_values jsonb; copies jsonb; roots jsonb:='{}';
        accounts jsonb:='[]'; value record; item record; manifest jsonb;
        root_id uuid; root_version integer; label text; result jsonb; policy bytea;
        inline_choice boolean; node_fields jsonb; owner_kind text; release_role text;
BEGIN
    metadata:=wormhole_data.connection_snapshot(p_node,p_user,p_epoch,p_change_seq);
    SELECT m.signed_profile INTO STRICT policy FROM wormhole_data.workspace_meta m WHERE m.singleton;
    IF metadata#>>'{plan,tunnelId}'<>'' THEN
        RAISE EXCEPTION 'Tunnel release requires signed field material' USING ERRCODE='0A000';
    END IF;
    inline_choice:=metadata#>>'{plan,credential,kind}'='inline';
    IF inline_choice THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('node-fields',p_node,NULL,p_epoch,p_change_seq);
        node_fields:=wormhole_data.catalog_projection_wire(to_jsonb(item));
    END IF;
    SELECT s.* INTO account FROM wormhole_data.user_key_states s WHERE s.user_id=p_user;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    state:=convert_from(account.signed_state,'UTF8')::jsonb;
    holder_id:=(state#>>'{encryption,id}')::uuid;holder_version:=(state#>>'{encryption,version}')::integer;
    IF holder_id IS NULL OR holder_version IS NULL OR holder_version<1 THEN RAISE EXCEPTION 'Account key selection unavailable' USING ERRCODE='WH010'; END IF;
    FOREACH role_name IN ARRAY ARRAY['primary','gateway'] LOOP
        profile_row:=metadata->(CASE role_name WHEN 'primary' THEN 'credential' ELSE 'gateway' END);
        owner_kind:='credential';release_role:=role_name;
        IF role_name='primary' AND inline_choice THEN
            profile_row:=node_fields;owner_kind:='node';release_role:='inline';
        END IF;
        IF profile_row='null'::jsonb THEN CONTINUE; END IF;
        field_values:='[]';copies:='[]';
        SELECT convert_from(decode(b.value->>5,'hex'),'UTF8')::jsonb INTO STRICT manifest
            FROM jsonb_array_elements(metadata->'boundaries') b WHERE b.value->>1=profile_row->>5;
        FOR value IN SELECT * FROM wormhole_data.owner_values(owner_kind,(profile_row->>1)::uuid,p_epoch,p_change_seq) LOOP
            root_id:=(manifest#>>'{secret,key,id}')::uuid;root_version:=(manifest#>>'{secret,key,version}')::integer;
            IF NOT EXISTS(SELECT 1 FROM wormhole_data.key_copies c WHERE c.key_id=value.dek_id AND c.key_version=value.dek_version AND c.holder_key_id=root_id AND c.holder_key_version=root_version) THEN
                root_id:=(manifest#>>'{previousSecret,key,id}')::uuid;root_version:=(manifest#>>'{previousSecret,key,version}')::integer;
                IF root_id IS NULL OR root_version IS NULL THEN RAISE EXCEPTION 'DEK copy unavailable' USING ERRCODE='WH010'; END IF;
            END IF;
            SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(value.dek_id,value.dek_version,root_id,root_version,p_epoch,p_change_seq);
            copies:=copies||jsonb_build_array(wormhole_data.key_copy_wire(to_jsonb(item)));
            label:=root_id::text||'/'||root_version::text;
            IF NOT (roots ? label) THEN
                SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq);
                roots:=roots||jsonb_build_object(label,wormhole_data.key_copy_wire(to_jsonb(item)));
            END IF;
            field_values:=field_values||jsonb_build_array(jsonb_build_array(value.workspace_id::text,value.owner_id::text,value.epoch::text,value.change_seq::text,
                value.field,value.row_version::text,value.dek_id::text,value.dek_version::text,encode(value.envelope,'hex')));
        END LOOP;
        accounts:=accounts||jsonb_build_array(jsonb_build_object('account',release_role,'values',field_values,'copies',copies));
    END LOOP;
    result:=jsonb_build_object('formatVersion',2,'profile',encode(policy,'hex'),'metadata',metadata,
        'account',jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')),
        'roots',(SELECT COALESCE(jsonb_agg(r.value ORDER BY r.key COLLATE "C"),'[]'::jsonb) FROM jsonb_each(roots) r),'accounts',accounts);
    IF inline_choice THEN result:=result||jsonb_build_object('formatVersion',3,'nodeFields',node_fields); END IF;
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'Credential release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$graph$;
REVOKE ALL ON FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=39 WHERE singleton;
COMMIT;
