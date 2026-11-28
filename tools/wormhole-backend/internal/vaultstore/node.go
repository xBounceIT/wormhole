package vaultstore

import "context"

// NodeMetadata preserves NULL inheritance separately from explicit false/zero.
// Secrets and notes belong to SecretValues, never to this metadata value.
type NodeMetadata struct {
	ID                      string               `json:"id"`
	ParentID                *string              `json:"parentId"`
	OwnerUserID             *string              `json:"ownerUserId"`
	Name                    string               `json:"name"`
	Kind                    int                  `json:"kind"`
	SortOrder               int64                `json:"sortOrder"`
	Protocol                *int                 `json:"protocol"`
	Host                    *string              `json:"host"`
	Port                    *int                 `json:"port"`
	HTTPPath                *string              `json:"httpPath"`
	Username                *string              `json:"username"`
	CredentialID            *string              `json:"credentialId"`
	CredentialMode          *int                 `json:"credentialMode"`
	CredentialSlotID        *string              `json:"credentialSlotId"`
	UseInlinePassword       *bool                `json:"useInlinePassword"`
	SshAutoSudo             *bool                `json:"sshAutoSudo"`
	HTTPIgnoreCertErrors    *bool                `json:"httpIgnoreCertErrors"`
	TunnelEnabled           *bool                `json:"tunnelEnabled"`
	TunnelConfigID          *string              `json:"tunnelConfigId"`
	SerialBaudRate          *int                 `json:"serialBaudRate"`
	SerialDataBits          *int                 `json:"serialDataBits"`
	SerialStopBits          *int                 `json:"serialStopBits"`
	SerialParity            *int                 `json:"serialParity"`
	SerialFlowControl       *int                 `json:"serialFlowControl"`
	SshKeyFileName          *string              `json:"sshKeyFileName"`
	SshKnownHostFingerprint *string              `json:"sshKnownHostFingerprint"`
	RDPDomain               *string              `json:"rdpDomain"`
	RDPScreenSize           *string              `json:"rdpScreenSize"`
	RDPFullScreen           *bool                `json:"rdpFullScreen"`
	RDPColorDepth           *int                 `json:"rdpColorDepth"`
	RDPUseAllMonitors       *bool                `json:"rdpUseAllMonitors"`
	RDPAudioMode            *int                 `json:"rdpAudioMode"`
	RDPAudioCaptureMode     *int                 `json:"rdpAudioCaptureMode"`
	RDPKeyboardHookMode     *int                 `json:"rdpKeyboardHookMode"`
	RDPRedirectClipboard    *bool                `json:"rdpRedirectClipboard"`
	RDPRedirectPrinters     *bool                `json:"rdpRedirectPrinters"`
	RDPRedirectSmartCards   *bool                `json:"rdpRedirectSmartCards"`
	RDPRedirectPorts        *bool                `json:"rdpRedirectPorts"`
	RDPRedirectDevices      *bool                `json:"rdpRedirectDevices"`
	RDPRedirectDrives       *string              `json:"rdpRedirectDrives"`
	RDPConnectionSpeed      *int                 `json:"rdpConnectionSpeed"`
	RDPDesktopBackground    *bool                `json:"rdpDesktopBackground"`
	RDPFontSmoothing        *bool                `json:"rdpFontSmoothing"`
	RDPDesktopComposition   *bool                `json:"rdpDesktopComposition"`
	RDPWindowDrag           *bool                `json:"rdpWindowDrag"`
	RDPMenuAnimation        *bool                `json:"rdpMenuAnimation"`
	RDPVisualStyles         *bool                `json:"rdpVisualStyles"`
	RDPBitmapCaching        *bool                `json:"rdpBitmapCaching"`
	RDPAutoReconnect        *bool                `json:"rdpAutoReconnect"`
	RDPServerAuthentication *int                 `json:"rdpServerAuthentication"`
	RDPGatewayUsageMethod   *int                 `json:"rdpGatewayUsageMethod"`
	RDPGatewayHostname      *string              `json:"rdpGatewayHostname"`
	RDPGatewayCredentialID  *string              `json:"rdpGatewayCredentialId"`
	RDPGatewayBypassLocal   *bool                `json:"rdpGatewayBypassLocal"`
	RDPGatewayUseSameCreds  *bool                `json:"rdpGatewayUseSameCreds"`
	RDPUseExternalClient    *bool                `json:"rdpUseExternalClient"`
	Imported                *NodeImportReference `json:"imported,omitempty"`
}

// NodeImportReference binds a shared node's separately stored import data to
// its ordinary metadata seal. Omitting it preserves existing seal bytes.
type NodeImportReference struct {
	Digest       string `json:"digest"`
	RetainedPins bool   `json:"retainedPins"`
	NoteVersion  uint64 `json:"noteVersion,omitempty"`
}

type Node struct {
	NodeMetadata
	CreatedAt            string        `json:"createdAt"`
	UpdatedAt            string        `json:"updatedAt"`
	RowVersion           uint64        `json:"rowVersion"`
	Deleted              bool          `json:"deleted"`
	Fields               []SecretField `json:"fields"`
	SealSuite            int           `json:"sealSuite"`
	SealSignerKeyID      string        `json:"sealSignerKeyId"`
	SealSignerKeyVersion uint32        `json:"sealSignerKeyVersion"`
	SealCapabilityID     *string       `json:"sealCapabilityId"`
	Seal                 []byte        `json:"seal"`
}

const MaxNodeDepth = 128

type NodeStore interface {
	Store
	ReadNode(context.Context, string) (Node, error)
	ListNodes(context.Context, string, int) ([]Node, error)
	WriteNode(context.Context, Node, []Secret, uint64) error
}

type SecretReader func(context.Context, SecretRef) (Secret, error)

// NodeDeletion prepares an authenticated tombstone and encrypted empty fields.
// Both arguments are borrowed only for this synchronous callback. The reader is
// restricted to this node within the transaction. Callbacks must not reenter the
// store, retain the reader, or perform external side effects: any later failure
// rolls back the entire tree, including previously prepared deletions.
type NodeDeletion func(Node, SecretReader) (Node, []Secret, error)

type NodeTreeStore interface {
	NodeStore
	DeleteNodeTree(context.Context, string, uint64, NodeDeletion) (uint64, error)
}

// NodeRevision binds an action to the node version observed by its caller.
type NodeRevision struct {
	ID         string
	RowVersion uint64
}

const MaxNodeDeleteRoots = 4096

type NodeTreesStore interface {
	NodeTreeStore
	DeleteNodeTrees(context.Context, []NodeRevision, NodeDeletion) (uint64, error)
}

const NodeResolverMigrationField = "resolverMigration"

func NodeEditableField(name string) bool { return name == "inlinePassword" || name == "notes" }
func NodeSecretField(name string) bool {
	return NodeEditableField(name) || name == NodeResolverMigrationField
}
