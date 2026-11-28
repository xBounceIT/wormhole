package sharedpg

import (
	"bytes"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// InvitationEnrollment is public pre-login context, never the code or a verifier.
// The temporary role is deterministic and cannot be replaced by a device/admin
// role through invitation fields. Database grants enforce enrollment-only access.
type InvitationEnrollment struct {
	RoleTag string              `json:"roleTag"`
	Context vault.InviteContext `json:"context"`
}

func (i Invitation) validEnrollment() bool {
	e := i.Enrollment
	if e == nil || len(e.RoleTag) < 8 || len(e.RoleTag) > 16 {
		return false
	}
	for _, ch := range e.RoleTag {
		if !(ch >= 'a' && ch <= 'z' || ch >= '2' && ch <= '7') {
			return false
		}
	}
	c := e.Context
	return c.WorkspaceID == i.WorkspaceID && c.LoginName == i.LoginName && c.UserID != uuid.Nil && c.InviteID != uuid.Nil && c.KeyID != uuid.Nil && c.KeyVersion != 0
}

// EnrollmentRole rechecks expiry before exposing the intended temporary role.
func (i Invitation) EnrollmentRole(now time.Time) (string, error) {
	if i.Validate(now) != nil || (i.FormatVersion != 2 && i.FormatVersion != 3) {
		return "", ErrInvitation
	}
	return "wh_" + i.Enrollment.RoleTag + "_i_" + i.Enrollment.Context.InviteID.String(), nil
}

func (i Invitation) enrollmentMaterial(code []byte, now time.Time) (string, []byte, error) {
	role, err := i.EnrollmentRole(now)
	if err != nil {
		return "", nil, err
	}
	material, err := vault.DeriveInviteLogin(code, i.Enrollment.Context)
	if err != nil {
		return "", nil, ErrInvitation
	}
	return role, material, nil
}

// EnrollmentLogin returns a native-only transport snapshot and SCRAM password.
// The caller must wipe the password. The one-time code is never sent to PostgreSQL
// and this password cannot decrypt the independently derived bootstrap envelope.
func (i Invitation) EnrollmentLogin(code []byte, now time.Time) (Settings, []byte, error) {
	role, material, err := i.enrollmentMaterial(code, now)
	if err != nil {
		return Settings{}, nil, err
	}
	defer vault.Wipe(material)
	login, err := EncodeLoginSecret(material)
	if err != nil {
		return Settings{}, nil, err
	}
	settings := Settings{Endpoints: append([]Endpoint(nil), i.Endpoints...), Database: i.Database, DeviceRole: role, TLS: i.TLS, Profile: vault.Default, CAPEM: bytes.Clone(i.CAPEM)}
	if i.FormatVersion == 3 {
		settings.TLSBundle, err = i.invitationTLSHint()
		if err != nil {
			vault.Wipe(login)
			return Settings{}, nil, err
		}
	}
	return settings, login, nil
}

// EnrollmentVerifier is for native provisioning. Return only the SCRAM verifier
// to the database; never log it and wipe it after the provisioning transaction.
func (i Invitation) EnrollmentVerifier(code []byte, now time.Time) (string, []byte, error) {
	role, material, err := i.enrollmentMaterial(code, now)
	if err != nil {
		return "", nil, err
	}
	defer vault.Wipe(material)
	verifier, err := NewSCRAMVerifier(material)
	if err != nil {
		return "", nil, err
	}
	return role, verifier, nil
}
