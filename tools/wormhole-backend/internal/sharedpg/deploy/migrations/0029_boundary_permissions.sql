-- Version 29: boundary permissions for connection accounts.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>28 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.boundaries (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    owner_user_id uuid NULL REFERENCES wormhole_data.users(id),
    deleted boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1)
);
CREATE TABLE wormhole_data.boundary_grants (
    boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
    user_id uuid NULL REFERENCES wormhole_data.users(id),
    group_id uuid NULL REFERENCES wormhole_data.groups(id),
    permissions integer NOT NULL CHECK(permissions BETWEEN 1 AND 31),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    signer_key_id uuid NULL,
    signer_key_version integer NULL,
    signature bytea NULL CHECK(signature IS NULL OR octet_length(signature)=64),
    CHECK(num_nonnulls(user_id,group_id)=1),
    FOREIGN KEY(signer_key_id,signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    CHECK(num_nonnulls(signer_key_id,signer_key_version,signature) IN (0,3)),
    UNIQUE NULLS NOT DISTINCT(boundary_id,user_id,group_id)
);
CREATE INDEX boundary_grants_user ON wormhole_data.boundary_grants(user_id,boundary_id);
CREATE INDEX boundary_grants_group ON wormhole_data.boundary_grants(group_id,boundary_id);
-- Expand without inventing unsigned boundary/key ownership for older experimental
-- records. Unregistered legacy boundaries deny release. Provisioning must create
-- real boundaries; new inserts/changed boundary references are checked immediately.
ALTER TABLE wormhole_data.nodes ADD CONSTRAINT nodes_boundary_fk FOREIGN KEY(boundary_id) REFERENCES wormhole_data.boundaries(id) NOT VALID;
ALTER TABLE wormhole_data.credential_profiles ADD CONSTRAINT credential_profiles_boundary_fk FOREIGN KEY(boundary_id) REFERENCES wormhole_data.boundaries(id) NOT VALID;
ALTER TABLE wormhole_data.credential_slots ADD CONSTRAINT credential_slots_boundary_fk FOREIGN KEY(boundary_id) REFERENCES wormhole_data.boundaries(id) NOT VALID;
ALTER TABLE wormhole_data.credential_slot_values ADD CONSTRAINT credential_slot_values_boundary_fk FOREIGN KEY(boundary_id) REFERENCES wormhole_data.boundaries(id) NOT VALID;
ALTER TABLE wormhole_data.user_node_overrides ADD CONSTRAINT user_node_overrides_boundary_fk FOREIGN KEY(boundary_id) REFERENCES wormhole_data.boundaries(id) NOT VALID;
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.boundaries
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.boundary_grants
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();

-- Boundary grants are independent of node grants. Personal boundaries cannot be
-- shared by a DB grant to another user, mirroring personal subtree confinement.
-- Signed escrow and cryptographic key access are separate from these DB-only rules.
CREATE FUNCTION wormhole_data.effective_boundary_permissions(p_user uuid,p_boundary uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $boundary$
DECLARE item record; result integer;
BEGIN
    IF p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid
       OR p_boundary IS NULL OR p_boundary='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid boundary permission request' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM wormhole_data.users u WHERE u.id=p_user AND NOT u.disabled;
    IF NOT FOUND THEN RETURN 0; END IF;
    SELECT b.* INTO item FROM wormhole_data.boundaries b WHERE b.id=p_boundary FOR SHARE NOWAIT;
    IF NOT FOUND THEN RETURN 0; END IF;
    IF item.deleted OR (item.owner_user_id IS NOT NULL AND item.owner_user_id<>p_user) THEN RETURN 0; END IF;
    SELECT COALESCE(bit_or(g.permissions),0) INTO result FROM wormhole_data.boundary_grants g
        WHERE g.boundary_id=p_boundary AND (g.user_id=p_user OR EXISTS(
            SELECT 1 FROM wormhole_data.group_members m WHERE m.group_id=g.group_id AND m.user_id=p_user));
    RETURN result;
END
$boundary$;

-- Internal account gate for the eventual audited release builder, not an API:
-- the device capability, never a caller-selected user, supplies identity. Require
-- Use or Reveal independently on the node and every selected account boundary.
-- Tunnel material, manifests, key copies, audit/ticket claiming and native signature
-- verification must also succeed before a public release can return ciphertext.
CREATE FUNCTION wormhole_data.connection_account_permissions(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint,p_permission integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $accounts$
DECLARE identity record; meta record; plan jsonb; target_boundary uuid; credential_id uuid;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_permission IS NULL OR p_permission NOT IN (2,8) OR p_node IS NULL
       OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid account permission request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004'; END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013'; END IF;
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&p_permission)<>p_permission THEN
        RAISE EXCEPTION 'Connection permission required' USING ERRCODE='42501';
    END IF;
    plan:=wormhole_data.resolve_connection(p_node,identity.user_id,p_epoch,p_change_seq);
    IF plan#>>'{credential,kind}' IN ('saved','override') THEN
        credential_id:=(plan#>>'{credential,id}')::uuid;
        SELECT c.boundary_id INTO STRICT target_boundary FROM wormhole_data.credential_profiles c WHERE c.id=credential_id;
    ELSIF plan#>>'{credential,kind}'='inline' THEN
        SELECT n.boundary_id INTO STRICT target_boundary FROM wormhole_data.nodes n WHERE n.id=p_node;
    END IF;
    IF target_boundary IS NOT NULL AND (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
        RAISE EXCEPTION 'Credential boundary permission required' USING ERRCODE='42501';
    END IF;
    IF plan->>'gatewayCredentialId'<>'' THEN
        SELECT c.boundary_id INTO STRICT target_boundary FROM wormhole_data.credential_profiles c WHERE c.id=(plan->>'gatewayCredentialId')::uuid;
        IF (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
            RAISE EXCEPTION 'Gateway boundary permission required' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN plan;
END
$accounts$;
REVOKE ALL ON TABLE wormhole_data.boundaries,wormhole_data.boundary_grants FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_data.effective_boundary_permissions(uuid,uuid),wormhole_data.connection_account_permissions(bytea,uuid,bigint,bigint,integer) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=29 WHERE singleton;
COMMIT;
