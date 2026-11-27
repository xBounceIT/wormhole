package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0088_update_node.sql
var updateNodeTemplate string

//go:embed fragments/ed25519_verify.sql
var ed25519VerifyDefinition string

//go:embed fragments/node_edit_message.sql
var nodeEditMessageDefinition string

//go:embed fragments/node_edit_bindings.sql
var nodeEditBindingsTemplate string

//go:embed fragments/node_edit_slot_authority.sql
var nodeEditSlotAuthority string

//go:embed fragments/node_direct_selection.sql
var nodeDirectSelection string

//go:embed fragments/node_edit_verify_seals.sql
var nodeEditVerifySeals string

//go:embed fragments/read_node_edit.sql
var readNodeEditTemplate string

func readNodeEdit(includeFolderFields bool) string {
	replace := ""
	fields := `        SELECT wormhole_data.catalog_projection_wire(to_jsonb(f)) INTO STRICT field_row
            FROM wormhole_data.selection_record('node-fields',p_node,NULL,meta.epoch,meta.change_seq) f;`
	if includeFolderFields {
		replace = "OR REPLACE "
		// Imported folders also carry a signed field manifest. Read its public
		// verification material here without expanding any secret-release API.
		fields = `        SELECT wormhole_data.catalog_projection_wire(to_jsonb(f)||to_jsonb(a)||jsonb_build_object(
            'workspace_id',meta.workspace_id,'subject_id',p_node,'epoch',meta.epoch,'change_seq',meta.change_seq,
            'record',jsonb_build_object('nodeId',p_node,'fields',f.fields,'deleted',f.deleted))) INTO STRICT field_row
        FROM wormhole_data.node_secret_manifests f
        CROSS JOIN LATERAL wormhole_data.node_author_material(f.seal_signer_key_id,f.seal_signer_key_version) a
        WHERE f.node_id=p_node AND f.row_version=n.row_version AND f.boundary_id=n.boundary_id;`
	}
	return strings.NewReplacer("{{REPLACE_READ}}", replace, "{{READ_FIELD_ROW}}", fields).Replace(strings.TrimSpace(readNodeEditTemplate))
}

func nodeEditBindings(version int) string {
	var arg, typ, mask, replace, slotCheck, directSelection string
	users := "NOT u.disabled AND\n            (u.id=p_actor OR (wormhole_data.effective_permissions(u.id,leaf.id)&2)=2)"
	if version >= 89 {
		arg, typ = ",p_previous_masks jsonb", ",jsonb"
		mask = " & CASE WHEN p_previous_masks IS NULL THEN 31 ELSE COALESCE((p_previous_masks->>leaf.id::text)::integer,0) END"
		// Stored selections still bind the destination if Use is restored later.
		users = `u.id=p_actor OR (wormhole_data.effective_permissions(u.id,leaf.id)&2)=2
            OR EXISTS(SELECT FROM wormhole_data.user_node_overrides o WHERE o.user_id=u.id AND o.node_id=leaf.id AND NOT o.deleted)
            OR (base#>>'{credential,kind}'='slot' AND EXISTS(SELECT FROM wormhole_data.credential_slot_values v
                WHERE v.user_id=u.id AND v.slot_id=NULLIF(base#>>'{credential,id}','')::uuid AND NOT v.deleted))`
	}
	if version >= 97 {
		replace = "OR REPLACE "
		// The first resolution path is the protocol family (including SSH for
		// SFTP). Returning false lets an edit repair an incompatible old slot
		// while rejecting an incompatible resulting binding.
		slotCheck = "\n" + strings.TrimRight(nodeEditSlotAuthority, "\r\n")
	}
	if version >= 98 {
		directSelection = strings.TrimRight(nodeDirectSelection, "\r\n") + "\n"
	}
	return strings.NewReplacer("{{DIRECT_SELECTION_BINDING}}", directSelection, "{{REPLACE_BINDINGS}}", replace, "{{MASK_ARG}}", arg, "{{MASK_TYPE}}", typ,
		"{{PRIOR_MASK}}", mask, "{{BINDING_USERS}}", users, "{{UNASSIGNED_SLOT_CHECK}}", slotCheck).Replace(strings.TrimSpace(nodeEditBindingsTemplate))
}

var updateNodeMigration = strings.NewReplacer(
	"{{READ_NODE_EDIT}}", readNodeEdit(false),
	"{{ED25519_VERIFY}}", ed25519VerifyDefinition,
	"{{NODE_EDIT_MESSAGE}}", nodeEditMessageDefinition,
	"{{NODE_EDIT_BINDINGS}}", nodeEditBindings(88),
	"{{NODE_EDIT_VERIFY_SEALS}}", strings.TrimRight(nodeEditVerifySeals, "\r\n"),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("88"),
).Replace(updateNodeTemplate)

func UpdateNodeMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(updateNodeMigration, roleTag, workspaceID)
}

//go:embed migrations/0089_move_node.sql
var moveNodeTemplate string

var moveNodeMigration = strings.NewReplacer(
	"{{READ_NODE_EDIT}}", readNodeEdit(true),
	"{{NODE_MOVE_BINDINGS}}", nodeEditBindings(89),
	"{{NODE_EDIT_VERIFY_SEALS}}", strings.TrimRight(nodeEditVerifySeals, "\r\n"),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("89"),
).Replace(moveNodeTemplate)

func MoveNodeMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(moveNodeMigration, roleTag, workspaceID)
}
