-- Version 23: bounded resolution-chain projection and shared public metadata helpers.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>22 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;


-- Complete typed projection shared by display paging and secret resolution.
{{NODE_METADATA_DEFINITION}}

-- Public verification material only; the owning API supplies authorization.
CREATE FUNCTION wormhole_data.node_author_material(p_signer uuid,p_version integer)
RETURNS TABLE(author_id uuid,signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $material$
DECLARE signing record; state record;
BEGIN
    SELECT k.* INTO signing FROM wormhole_data.keys k
        WHERE k.key_id=p_signer AND k.key_version=p_version;
    IF NOT FOUND OR signing.kind<>'user-sign' OR signing.owner_id IS NULL THEN
        RAISE EXCEPTION 'Author key state unavailable' USING ERRCODE='WH010';
    END IF;
    SELECT s.* INTO state FROM wormhole_data.user_key_states s WHERE s.user_id=signing.owner_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Author key state unavailable' USING ERRCODE='WH010'; END IF;
    author_id:=signing.owner_id;
    signing_key_id:=signing.key_id; signing_key_version:=signing.key_version;
    state_sequence:=state.state_sequence; signed_state:=state.signed_state;
    -- Preserve signed revocations even if historical certificate material is
    -- missing. No account capsule or encrypted/private key material is returned.
    IF signing.suite=1 AND pg_catalog.octet_length(signing.public_key)=32
       AND signing.cert_signer_key_id IS NOT NULL AND signing.cert_signer_key_version IS NOT NULL
       AND signing.cert_revision IS NOT NULL AND pg_catalog.octet_length(signing.cert_signature)=64 THEN
        suite:=signing.suite; public_key:=signing.public_key;
        cert_signer_key_id:=signing.cert_signer_key_id; cert_signer_key_version:=signing.cert_signer_key_version;
        cert_revision:=signing.cert_revision; cert_signature:=signing.cert_signature;
    END IF;
    RETURN NEXT;
END
$material$;

CREATE OR REPLACE FUNCTION wormhole_api_v1.get_tree(p_capability bytea,p_after uuid DEFAULT NULL,
    p_epoch bigint DEFAULT NULL,p_change_seq bigint DEFAULT NULL,p_limit integer DEFAULT 32)
RETURNS TABLE(workspace_id uuid,user_id uuid,epoch bigint,change_seq bigint,resolver_version integer,
    has_more boolean,node jsonb,permissions integer,boundary_id uuid,row_version bigint,
    seal_suite smallint,seal_signer_key_id uuid,seal_signer_key_version integer,seal_capability_id uuid,seal bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $tree$
DECLARE identity record; meta record; ids uuid[]; masks integer[]; count integer; i integer; item wormhole_data.nodes;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_limit IS NULL OR p_limit<1 OR p_limit>32
       OR (p_after IS NULL AND (p_epoch IS NOT NULL OR p_change_seq IS NOT NULL))
       OR (p_after IS NOT NULL AND (p_after='00000000-0000-0000-0000-000000000000'::uuid OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0)) THEN
        RAISE EXCEPTION 'Invalid tree page request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_after IS NOT NULL AND (p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq) THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    SELECT pg_catalog.array_agg(visible.id ORDER BY visible.id),pg_catalog.array_agg(visible.mask ORDER BY visible.id)
    INTO ids,masks FROM (
        SELECT n.id,p.mask FROM wormhole_data.nodes n
        CROSS JOIN LATERAL (SELECT wormhole_data.effective_permissions(identity.user_id,n.id) AS mask OFFSET 0) p
        WHERE (p_after IS NULL OR n.id>p_after) AND (p.mask & 1)=1
        ORDER BY n.id LIMIT p_limit+1
    ) visible;
    count:=COALESCE(pg_catalog.cardinality(ids),0);
    workspace_id:=meta.workspace_id; user_id:=identity.user_id;
    epoch:=meta.epoch; change_seq:=meta.change_seq; resolver_version:=meta.resolver_version;
    has_more:=count>p_limit;
    IF count=0 THEN RETURN NEXT; RETURN; END IF;
    FOR i IN 1..LEAST(count,p_limit) LOOP
        SELECT n.* INTO STRICT item FROM wormhole_data.nodes n WHERE n.id=ids[i];
        IF item.encrypted_metadata IS NOT NULL THEN
            RAISE EXCEPTION 'Encrypted tree projection is not available' USING ERRCODE='0A000';
        END IF;
        IF item.seal IS NULL OR item.name IS NULL THEN
            RAISE EXCEPTION 'Node metadata is not provisioned' USING ERRCODE='WH014';
        END IF;
        node:=wormhole_data.node_metadata(item);
        permissions:=masks[i]; boundary_id:=item.boundary_id; row_version:=item.row_version;
        seal_suite:=item.seal_suite; seal_signer_key_id:=item.seal_signer_key_id;
        seal_signer_key_version:=item.seal_signer_key_version; seal_capability_id:=item.seal_capability_id; seal:=item.seal;
        RETURN NEXT;
    END LOOP;
END
$tree$;

CREATE OR REPLACE FUNCTION wormhole_api_v1.node_author(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,node_id uuid,author_id uuid,epoch bigint,change_seq bigint,
    signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,
    cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $author$
DECLARE identity record; meta record; item record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid author request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    -- Return the same refusal for hidden and nonexistent nodes.
    SELECT n.* INTO item FROM wormhole_data.nodes n WHERE n.id=p_node;
    IF NOT FOUND THEN RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014'; END IF;
    IF (wormhole_data.effective_permissions(identity.user_id,p_node) & 1)=0 OR item.seal IS NULL THEN
        RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
    END IF;
    RETURN QUERY SELECT meta.workspace_id,p_node,m.author_id,meta.epoch,meta.change_seq,
        m.signing_key_id,m.signing_key_version,m.state_sequence,m.signed_state,
        m.suite,m.public_key,m.cert_signer_key_id,m.cert_signer_key_version,m.cert_revision,m.cert_signature
        FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version) m;
END
$author$;

-- Private snapshot reader: only a future authorized, audited release API may
-- expose this chain. Reading ancestors is not authorized by View on the leaf.
CREATE FUNCTION wormhole_data.resolution_chain(p_node uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(depth integer,node_id uuid,node jsonb,boundary_id uuid,row_version bigint,
    seal_suite smallint,seal_signer_key_id uuid,seal_signer_key_version integer,seal_capability_id uuid,seal bytea,
    author_id uuid,signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $chain$
DECLARE meta record; item wormhole_data.nodes; author record; current_id uuid:=p_node;
        seen uuid[]:='{}'; step integer:=0; projected jsonb; size integer:=0;
BEGIN
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid resolution request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    WHILE current_id IS NOT NULL LOOP
        IF step>=128 OR current_id=ANY(seen) THEN
            RAISE EXCEPTION 'Invalid resolution chain' USING ERRCODE='WH016';
        END IF;
        SELECT n.* INTO item FROM wormhole_data.nodes n WHERE n.id=current_id;
        IF NOT FOUND OR item.seal IS NULL OR item.name IS NULL THEN
            RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
        END IF;
        IF item.encrypted_metadata IS NOT NULL THEN
            RAISE EXCEPTION 'Encrypted resolution projection is not available' USING ERRCODE='0A000';
        END IF;
        projected:=wormhole_data.node_metadata(item);
        IF NOT wormhole_data.resolver_node_valid(projected) OR item.kind<>(CASE WHEN step=0 THEN 1 ELSE 0 END) THEN
            RAISE EXCEPTION 'Invalid resolution chain' USING ERRCODE='WH016';
        END IF;
        SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
        -- Includes hex expansion and bounded scalar/JSON framing for native wire.
        size:=size+octet_length(projected::text)+2*octet_length(author.signed_state)+1024;
        IF size>8388608 THEN RAISE EXCEPTION 'Resolution chain is too large' USING ERRCODE='54000'; END IF;
        RETURN QUERY SELECT step,item.id,projected,item.boundary_id,item.row_version,item.seal_suite,
            item.seal_signer_key_id,item.seal_signer_key_version,item.seal_capability_id,item.seal,
            author.author_id,author.signing_key_id,author.signing_key_version,author.state_sequence,author.signed_state,
            author.suite,author.public_key,author.cert_signer_key_id,author.cert_signer_key_version,author.cert_revision,author.cert_signature;
        seen:=array_append(seen,current_id);current_id:=item.parent_id;step:=step+1;
    END LOOP;
END
$chain$;
REVOKE ALL ON FUNCTION wormhole_data.node_metadata(wormhole_data.nodes),wormhole_data.node_author_material(uuid,integer),wormhole_data.resolution_chain(uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
UPDATE wormhole_data.workspace_meta SET schema_version=23 WHERE singleton;
COMMIT;
