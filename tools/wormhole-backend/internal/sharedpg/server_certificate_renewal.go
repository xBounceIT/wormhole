package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrServerCertificateAuthority = errors.New("shared_server_certificate_authority_unavailable")

const serverCAArguments = `pg_catalog.decode($1,'hex'),$2::uuid,$3::integer,
		$4::uuid,$5::integer,$6::bigint,pg_catalog.decode($7,'hex'),pg_catalog.decode($8,'hex'),pg_catalog.decode($9,'hex')`

const serverCAKeyColumns = `org_key_id::text,org_key_version::text,
	pg_catalog.encode(enc,'hex'),pg_catalog.encode(ciphertext,'hex'),pg_catalog.encode(signature,'hex')`

const serverCertificateRenewalSQL = `SELECT ` + serverCAKeyColumns + `,ca::text
	FROM wormhole_api_v1.server_certificate_renewal(` + serverCAArguments + `)`

type serverCertificateRenewalMaterial struct {
	organisation vault.KeyRef
	copy         vault.SignedKeyCopy
	ca           workspaceCAKeyCopy
}

// RenewServerCertificate issues against the active, locally anchored TLS
// bundle. It borrows the authenticated device owner's user encryption key;
// PostgreSQL can supply only signed ciphertext and never receives the CSR or
// private keys. The caller must enforce the fresh effective profile.
func (s *Session) RenewServerCertificate(ctx context.Context, trust TrustState, verified *VerifiedTLSBundle, userPrivate, userSigningSeed, csr []byte, now time.Time) ([]byte, error) {
	if ctx == nil || len(userPrivate) != 32 || len(userSigningSeed) != ed25519.SeedSize {
		return nil, ErrConfiguration
	}
	account, err := authenticatedServerCAContext(trust, verified)
	if err != nil {
		return nil, err
	}
	// The previous certificate and the originally staged replacement are
	// deliberately distinct during overlap. Complete rotation before renewal.
	if len(verified.bundle.CAs) != 1 {
		return nil, ErrServerCertificateAuthority
	}
	dns, ips, err := serverCertificateNames(verified.bundle.Hosts)
	if err != nil {
		return nil, err
	}
	if _, err := approvedServerCSR(csr, dns, ips); err != nil {
		return nil, err
	}
	material, err := s.readServerCertificateRenewal(ctx, trust)
	if err != nil {
		return nil, err
	}
	// Join rewraps the organisation encryption key to the final account and
	// signs that copy with the final account key. The CA copy itself remains
	// signed under the pinned organisation key.
	if verified.bundle.WorkspaceCA != nil && material.ca.Key != verified.bundle.WorkspaceCA.Key {
		return nil, vault.ErrAuthentication
	}
	organisationPrivate, err := openServerCAOrgCopy(trust, material.organisation, material.copy, userPrivate, userSigningSeed)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(organisationPrivate)

	ca := WrappedWorkspaceCA{CertificateDER: verified.bundle.CAs[0], KeyCopy: material.ca.Copy}
	cert, err := x509.ParseCertificate(ca.CertificateDER)
	if err != nil {
		return nil, ErrServerCertificate
	}
	lifetime := min(serverCertValidity, cert.NotAfter.Sub(now.UTC().Truncate(time.Second)))
	caBinding := material.ca.binding(vault.OrganisationRecoveryBinding{
		WorkspaceID: trust.WorkspaceID, Encryption: material.organisation, Signing: account.Signer,
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signed, err := ca.IssueServerCertificate(caBinding, organisationPrivate, account.Organisation, csr, verified.bundle.Hosts, now, lifetime)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return signed, nil
}

func (s *Session) readServerCertificateRenewal(ctx context.Context, trust TrustState) (*serverCertificateRenewalMaterial, error) {
	var material *serverCertificateRenewalMaterial
	err := s.queryServerCA(ctx, trust, serverCertificateRenewalSQL, nil, 2048, 1, 6, func(rows [][][]byte) error {
		var err error
		material, err = parseServerCertificateRenewal(rows)
		return err
	})
	return material, err
}

func authenticatedServerCAContext(trust TrustState, verified *VerifiedTLSBundle) (vault.UserKeyTrust, error) {
	account, err := trust.AccountTrust()
	if err != nil || !trust.Account.Active {
		return vault.UserKeyTrust{}, vault.ErrAuthentication
	}
	policy, err := trust.Policy()
	if err != nil || trust.Enrollment == nil || (policy.Profile != vault.Default && policy.Profile != vault.Standard) {
		return vault.UserKeyTrust{}, ErrServerCertificateAuthority
	}
	pin := verified.Pin()
	if trust.TLSSequence == 0 || pin.WorkspaceID != trust.WorkspaceID || pin.Signer != account.Signer ||
		pin.MinimumSequence != trust.TLSSequence || !bytes.Equal(pin.Digest, trust.TLSDigest) ||
		!bytes.Equal(pin.Organisation, account.Organisation) {
		return vault.UserKeyTrust{}, vault.ErrAuthentication
	}
	return account, nil
}

func openServerCAOrgCopy(trust TrustState, key vault.KeyRef, copy vault.SignedKeyCopy, userPrivate, signingSeed []byte) ([]byte, error) {
	userSigningKey := ed25519.NewKeyFromSeed(signingSeed)
	defer vault.Wipe(userSigningKey)
	binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: key, Holder: trust.Enrollment.Encryption, Issuer: trust.Enrollment.Signing}
	return vault.OpenKeyCopy(userPrivate, binding, copy, userSigningKey.Public().(ed25519.PublicKey))
}

func (s *Session) queryServerCA(ctx context.Context, trust TrustState, statement string, extra [][]byte, byteLimit, rowLimit, columnLimit int, consume func([][][]byte) error) error {
	state, err := vault.EncodeUserKeyState(*trust.Account)
	if err != nil {
		return err
	}
	stateDigest := sha256.Sum256(state)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	if s.capability == nil || s.authEpoch == 0 || s.admission.WorkspaceID != trust.WorkspaceID ||
		s.admission.UserID != trust.UserID || s.admission.DeviceID != trust.DeviceID {
		return ErrAuthentication
	}
	owned, opCtx, release, err := s.lease(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrQuery
	}
	var rows [][][]byte
	err = s.capability.With(func(capability []byte) error {
		encoded := hex.AppendEncode(nil, capability)
		defer vault.Wipe(encoded)
		holder, signer := trust.Enrollment.Encryption, trust.Enrollment.Signing
		params := [][]byte{encoded, []byte(holder.ID.String()), strconv.AppendUint(nil, uint64(holder.Version), 10),
			[]byte(signer.ID.String()), strconv.AppendUint(nil, uint64(signer.Version), 10),
			strconv.AppendUint(nil, trust.TLSSequence, 10), hex.AppendEncode(nil, trust.TLSDigest), hex.AppendEncode(nil, trust.PolicyDigest),
			hex.AppendEncode(nil, stateDigest[:])}
		var queryErr error
		rows, queryErr = s.queryLeasedWithLimits(opCtx, conn, statement, append(params, extra...), byteLimit, rowLimit, columnLimit)
		return queryErr
	})
	defer wipeQueryRows(rows)
	if err != nil {
		return err
	}
	if err = consume(rows); err != nil {
		s.discardConnection(conn)
	}
	return err
}

func parseServerCertificateRenewal(rows [][][]byte) (*serverCertificateRenewalMaterial, error) {
	if len(rows) != 1 || len(rows[0]) != 6 {
		return nil, ErrAdmissionResponse
	}
	r := rows[0]
	key, copy, err := parseServerCAOrgCopy(r[:5])
	var ca workspaceCAKeyCopy
	if err != nil || len(r[5]) > maxBootstrapRecoveryBytes || json.Unmarshal(r[5], &ca) != nil || ca.Key.ID == uuid.Nil || ca.Key.Version != 1 {
		return nil, ErrAdmissionResponse
	}
	return &serverCertificateRenewalMaterial{organisation: key, copy: copy, ca: ca}, nil
}

func parseServerCAOrgCopy(row [][]byte) (vault.KeyRef, vault.SignedKeyCopy, error) {
	id, idOK := treeID(row[0])
	version, versionOK := treeNumber(row[1], 1, math.MaxInt32)
	if !idOK || !versionOK || len(row[2]) != 64 || len(row[3]) != 96 || len(row[4]) != 128 {
		return vault.KeyRef{}, vault.SignedKeyCopy{}, ErrAdmissionResponse
	}
	enc, encErr := hex.DecodeString(string(row[2]))
	body, bodyErr := hex.DecodeString(string(row[3]))
	signature, sigErr := hex.DecodeString(string(row[4]))
	if encErr != nil || bodyErr != nil || sigErr != nil {
		return vault.KeyRef{}, vault.SignedKeyCopy{}, ErrAdmissionResponse
	}
	return vault.KeyRef{ID: id, Version: uint32(version)}, vault.SignedKeyCopy{
		Envelope:  vault.SealedBundle{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: enc, Ciphertext: body},
		Signature: signature,
	}, nil
}
