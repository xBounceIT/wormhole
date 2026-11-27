package resolver

// CredentialSlot and CredentialSlotValue contain resolution metadata only.
// Callers must authenticate their seals and authorize Use on the selected
// credential boundary before releasing a secret. AllowSelfService governs writes,
// not whether an administrator-assigned value can be used.
type CredentialSlot struct {
	ID                  string `json:"id"`
	Protocol            string `json:"protocol"`
	DefaultCredentialID string `json:"defaultCredentialId"`
	AllowSelfService    bool   `json:"allowSelfService"`
}

type CredentialSlotValue struct {
	SlotID       string `json:"slotId"`
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
}

// ResolveSlot consumes a plan produced by Resolve from an authenticated chain.
// It selects exactly the current user's assignment, or the default only
// when no assignment exists. Malformed/mismatched assignments never fall back.
// The resulting saved choice keeps its originating node. Its identity components
// are reset so ApplyCredential cannot pair another account's username/domain with
// the selected secret. The caller retains the signed slot/value as provenance.
func ResolveSlot(plan Plan, user string, slot CredentialSlot, value *CredentialSlotValue) (Plan, error) {
	if plan.Version != Version || !canonicalID(plan.NodeID) || !canonicalID(plan.Credential.NodeID) ||
		!canonicalID(user) || plan.Credential.Kind != "slot" || !canonicalID(slot.ID) ||
		plan.Credential.ID != slot.ID || slot.Protocol == "" || slot.Protocol != CredentialProtocol(plan.Protocol) ||
		(slot.DefaultCredentialID != "" && !canonicalID(slot.DefaultCredentialID)) {
		return Plan{}, ErrCredential
	}
	selected := slot.DefaultCredentialID
	if value != nil {
		if value.SlotID != slot.ID || value.UserID != user || !canonicalID(value.CredentialID) {
			return Plan{}, ErrCredential
		}
		selected = value.CredentialID
	}
	if selected == "" {
		return Plan{}, ErrCredential
	}
	plan.Credential.Kind = "saved"
	plan.Credential.ID = selected
	plan.Username = ""
	plan.Domain = ""
	return plan, nil
}
