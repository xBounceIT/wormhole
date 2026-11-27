-- Version 40: signed tunnel profiles and audited settings release.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>39 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Public provider metadata is separately signed. ConfigurationVersion identifies
-- the sole encrypted settings field and can remain stable across metadata edits.
CREATE TABLE wormhole_data.tunnel_profiles (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 name text NOT NULL CHECK(octet_length(name)<=512 AND char_length(name)<=128 AND btrim(name)<>''),
 kind smallint NOT NULL CHECK(kind BETWEEN 0 AND 8),
 configuration_version bigint NOT NULL CHECK(configuration_version>=1 AND configuration_version<=row_version),
 deleted boolean NOT NULL DEFAULT false,
 boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
 row_version bigint NOT NULL CHECK(row_version>=1),
 seal_suite smallint NOT NULL CHECK(seal_suite=2),
 seal_signer_key_id uuid NOT NULL,
 seal_signer_key_version integer NOT NULL,
 seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 seal bytea NOT NULL CHECK(octet_length(seal)=64),
 FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.tunnel_profiles
 FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
REVOKE ALL ON TABLE wormhole_data.tunnel_profiles FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;

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
    IF p_kind IS NULL OR p_kind NOT IN ('slot','slot-value','override','node-fields','tunnel')
       OR p_subject IS NULL OR p_subject='00000000-0000-0000-0000-000000000000'::uuid
       OR (p_kind IN ('slot','node-fields','tunnel') AND p_user IS NOT NULL)
       OR (p_kind NOT IN ('slot','node-fields','tunnel') AND (p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid))
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
    ELSIF p_kind='tunnel' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('metadata',jsonb_build_object('id',s.id,'name',s.name,'kind',s.kind),'configurationVersion',s.configuration_version,'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.tunnel_profiles s WHERE s.id=p_subject;
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

CREATE OR REPLACE FUNCTION wormhole_data.owner_values(p_kind text,p_owner uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,owner_id uuid,epoch bigint,change_seq bigint,
    field text,row_version bigint,dek_id uuid,dek_version integer,envelope bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $values$
DECLARE profile record; entry jsonb; value wormhole_data.secret_values; size bigint:=0; fields jsonb;
BEGIN
    -- Validates ID/snapshot/readiness/API and locks workspace against all writers.
    IF p_kind='credential' THEN
        SELECT * INTO STRICT profile FROM wormhole_data.credential_record(p_owner,p_epoch,p_change_seq);
    ELSIF p_kind='node' THEN
        SELECT * INTO STRICT profile FROM wormhole_data.selection_record('node-fields',p_owner,NULL,p_epoch,p_change_seq);
    ELSIF p_kind='tunnel' THEN
        SELECT * INTO STRICT profile FROM wormhole_data.selection_record('tunnel',p_owner,NULL,p_epoch,p_change_seq);
    ELSE
        RAISE EXCEPTION 'Invalid value owner' USING ERRCODE='22023';
    END IF;
    IF (profile.record->>'deleted')::boolean THEN RAISE EXCEPTION 'Credential unavailable' USING ERRCODE='WH018'; END IF;
    fields:=profile.record->'fields';
    IF p_kind='tunnel' THEN
        fields:=jsonb_build_array(jsonb_build_object('field','settings','version',profile.record->'configurationVersion','present',true));
    END IF;
    FOR entry IN SELECT f.value FROM jsonb_array_elements(fields) f LOOP
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

CREATE OR REPLACE FUNCTION wormhole_data.connection_snapshot(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $snapshot$
DECLARE meta record; plan jsonb; base_plan jsonb; chain jsonb; chain_body jsonb;
        override_row jsonb; slot_row jsonb; value_row jsonb; credential_row jsonb; gateway_row jsonb;
        boundaries jsonb; required uuid[]; item record; target_slot uuid;
        tunnel_row jsonb; override_id text:=''; result jsonb;
BEGIN
    -- Validates every argument and locks the requested workspace snapshot.
    plan:=wormhole_data.resolve_connection(p_node,p_user,p_epoch,p_change_seq);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    SELECT jsonb_agg(wormhole_data.catalog_projection_wire(to_jsonb(c)||jsonb_build_object(
            'workspace_id',meta.workspace_id,'subject_id',c.node_id,'epoch',p_epoch,'change_seq',p_change_seq,'record',c.node)) ORDER BY c.depth),
        jsonb_agg(c.node ORDER BY c.depth),array_agg(c.boundary_id ORDER BY c.depth)
    INTO chain,chain_body,required FROM wormhole_data.resolution_chain(p_node,p_epoch,p_change_seq) c;
    IF EXISTS(SELECT 1 FROM wormhole_data.user_node_overrides o WHERE o.node_id=p_node AND o.user_id=p_user) THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('override',p_node,p_user,p_epoch,p_change_seq);
        override_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        IF NOT (item.record->>'deleted')::boolean THEN override_id:=item.record->>'credentialId'; END IF;
    END IF;
    base_plan:=wormhole_data.resolve_chain(chain_body,override_id);
    IF base_plan#>>'{credential,kind}'='slot' THEN
        target_slot:=(base_plan#>>'{credential,id}')::uuid;
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('slot',target_slot,NULL,p_epoch,p_change_seq);
        slot_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        IF EXISTS(SELECT 1 FROM wormhole_data.credential_slot_values v WHERE v.slot_id=target_slot AND v.user_id=p_user) THEN
            SELECT * INTO STRICT item FROM wormhole_data.selection_record('slot-value',target_slot,p_user,p_epoch,p_change_seq);
            value_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        END IF;
    END IF;
    IF plan#>>'{credential,kind}' IN ('saved','override') THEN
        SELECT * INTO STRICT item FROM wormhole_data.credential_record((plan#>>'{credential,id}')::uuid,p_epoch,p_change_seq);
        credential_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    IF plan->>'gatewayCredentialId'<>'' THEN
        SELECT * INTO STRICT item FROM wormhole_data.credential_record((plan->>'gatewayCredentialId')::uuid,p_epoch,p_change_seq);
        gateway_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    IF plan->>'tunnelId'<>'' THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('tunnel',(plan->>'tunnelId')::uuid,NULL,p_epoch,p_change_seq);
        tunnel_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    SELECT jsonb_agg(jsonb_build_array(b.workspace_id::text,b.boundary_id::text,b.epoch::text,b.change_seq::text,
        b.version::text,encode(b.body,'hex'),b.signer_key_id::text,b.signer_key_version::text,encode(b.signature,'hex')) ORDER BY b.boundary_id)
    INTO boundaries FROM (SELECT DISTINCT unnest(required) AS id) r
        CROSS JOIN LATERAL wormhole_data.boundary_manifest(r.id,p_epoch,p_change_seq) b;
    result:=jsonb_build_object('formatVersion',1,'workspaceId',meta.workspace_id::text,'userId',p_user::text,
        'nodeId',p_node::text,'epoch',p_epoch::text,'changeSeq',p_change_seq::text,'plan',plan,'chain',chain,
        'override',override_row,'slot',slot_row,'slotValue',value_row,'credential',credential_row,'gateway',gateway_row,'boundaries',boundaries);
    IF tunnel_row IS NOT NULL THEN result:=result||jsonb_build_object('formatVersion',2,'tunnel',tunnel_row); END IF;
    IF octet_length(result::text)>16777216 THEN RAISE EXCEPTION 'Connection snapshot is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$snapshot$;
{{ACCOUNT_PERMISSIONS_DEFINITION}}
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
    FOREACH role_name IN ARRAY ARRAY['primary','gateway','tunnel'] LOOP
        profile_row:=metadata->(CASE role_name WHEN 'primary' THEN 'credential' WHEN 'gateway' THEN 'gateway' ELSE 'tunnel' END);
        owner_kind:='credential';release_role:=role_name;
        IF role_name='primary' AND inline_choice THEN
            profile_row:=node_fields;owner_kind:='node';release_role:='inline';
        END IF;
        IF profile_row IS NULL OR profile_row='null'::jsonb THEN CONTINUE; END IF;
        IF role_name='tunnel' THEN owner_kind:='tunnel'; END IF;
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
    IF metadata->>'formatVersion'='2' THEN result:=result||jsonb_build_object('formatVersion',4,'nodeFields',node_fields); END IF;
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'Credential release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$graph$;
REVOKE ALL ON FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=40 WHERE singleton;
COMMIT;
