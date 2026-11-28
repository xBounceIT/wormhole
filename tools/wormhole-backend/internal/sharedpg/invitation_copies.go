package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const invitationCopiesSQL = `SELECT key_id::text,key_version::text,holder_key_id::text,holder_key_version::text,issuer_key_id::text,issuer_key_version::text,suite::text,pg_catalog.encode(enc,'hex'),pg_catalog.encode(ciphertext,'hex'),pg_catalog.encode(signature,'hex') FROM wormhole_api_v1.enrollment_key_copies($1::uuid,$2::bigint,pg_catalog.decode($3,'hex'))`

// PrepareInvitationJoin downloads and authenticates the complete manifest-bound
// graph before preparing new user keys. It does not redeem or commit the invite.
// The caller owns the returned secret plan and must Wipe it on every terminal path.
func (s *Session) PrepareInvitationJoin(ctx context.Context, i Invitation, code []byte, minimumRevision uint64) (*vault.InviteRewrapPlan, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	bootstrap, err := s.InvitationBootstrap(ctx, i)
	if err != nil {
		return nil, err
	}
	opened, err := bootstrap.Authenticate(i, code, minimumRevision, time.Now())
	if err != nil {
		return nil, err
	}
	defer opened.Wipe()
	return s.prepareInvitationCopies(ctx, i, bootstrap, opened, minimumRevision)
}

func (s *Session) prepareInvitationCopies(ctx context.Context, i Invitation, bootstrap *UnverifiedInvitationBootstrap, opened *vault.InviteBootstrap, minimumRevision uint64) (*vault.InviteRewrapPlan, error) {
	raw, err := vault.EncodeInviteManifest(bootstrap.Manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	rows, err := s.Query(ctx, invitationCopiesSQL, [][]byte{[]byte(i.Enrollment.Context.InviteID.String()), []byte(strconv.FormatUint(bootstrap.Manifest.Revision, 10)), hex.AppendEncode(nil, digest[:])})
	defer wipeQueryRows(rows)
	if err != nil {
		return nil, err
	}
	copies, err := parseInvitationCopies(rows, bootstrap.Manifest)
	if err != nil {
		s.cancel()
		return nil, err
	}
	return vault.PrepareCertifiedInviteRewrap(ctx, i.Enrollment.Context, opened, bootstrap.Manifest, copies, minimumRevision, i.ExpiresAt, time.Now())
}

// Pair each row with authenticated manifest coordinates, never with row order or
// a server-provided issuer key. Signature/HPKE verification happens before rewrap.
func parseInvitationCopies(rows [][][]byte, m vault.InviteManifest) ([]vault.SignedKeyCopy, error) {
	if len(rows) != len(m.Copies) || len(rows) > vault.MaxInviteKeyCopies {
		return nil, ErrAdmissionResponse
	}
	expected := make(map[string]int, len(m.Copies))
	for n, b := range m.Copies {
		key := b.Key.ID.String() + "/" + strconv.FormatUint(uint64(b.Key.Version), 10)
		if _, found := expected[key]; found {
			return nil, ErrAdmissionResponse
		}
		expected[key] = n
	}
	result := make([]vault.SignedKeyCopy, len(rows))
	for _, row := range rows {
		if len(row) != 10 {
			return nil, ErrAdmissionResponse
		}
		key := string(row[0]) + "/" + string(row[1])
		index, ok := expected[key]
		if !ok {
			return nil, ErrAdmissionResponse
		}
		delete(expected, key)
		b := m.Copies[index]
		if string(row[2]) != b.Holder.ID.String() || string(row[3]) != strconv.FormatUint(uint64(b.Holder.Version), 10) || string(row[4]) != b.Issuer.ID.String() || string(row[5]) != strconv.FormatUint(uint64(b.Issuer.Version), 10) || string(row[6]) != "2" {
			return nil, ErrAdmissionResponse
		}
		var fields [3][]byte
		for n, size := range []int{32, 48, 64} {
			if len(row[7+n]) != 2*size {
				return nil, ErrAdmissionResponse
			}
			value, err := hex.DecodeString(string(row[7+n]))
			if err != nil {
				return nil, ErrAdmissionResponse
			}
			fields[n] = value
		}
		result[index] = vault.SignedKeyCopy{Envelope: vault.SealedBundle{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: fields[0], Ciphertext: fields[1]}, Signature: fields[2]}
	}
	return result, nil
}
