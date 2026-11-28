package main

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func readSharedAccountMaterial(ctx context.Context, session sharedAdmissionSession, current sharedpg.TrustState) (*sharedpg.UnverifiedAccountKeys, error) {
	if current.Enrollment != nil {
		return session.AccountEnrollmentMaterial(ctx)
	}
	if current.FormatVersion >= 5 {
		// A signed anchor reset retired the pin. Require explicit re-enrollment,
		// never reinterpret the bootstrap as an ordinary direct-certified account.
		return nil, sharedpg.ErrAccountRevision
	}
	return session.AccountUnlockMaterial(ctx)
}

// The caller has already authenticated/persisted account.State. Return the next
// protected floor together with owned private keys; persist before publishing.
func openSharedAccountKeys(master []byte, account *sharedpg.UnverifiedAccountKeys, current sharedpg.TrustState, minimumWrapping uint64) (*vault.UserKeys, sharedpg.TrustState, error) {
	if account == nil || account.State == nil {
		return nil, sharedpg.TrustState{}, sharedpg.ErrAdmissionResponse
	}
	trust, err := current.AccountTrust()
	if err != nil {
		return nil, sharedpg.TrustState{}, err
	}
	trust.MinimumWrappingRevision = max(trust.MinimumWrappingRevision, minimumWrapping)
	var keys *vault.UserKeys
	var next sharedpg.TrustState
	if current.Enrollment != nil {
		if account.EnrollmentCertificate == nil || account.EncryptionCertificate != nil || account.SigningCertificate != nil {
			return nil, sharedpg.TrustState{}, sharedpg.ErrAdmissionResponse
		}
		// Public certificate observations are independent of the encrypted
		// capsule. Its claimed wrapping revision is trusted only after GCM opens.
		next, err = current.AdvanceEnrollment(*account.EnrollmentCertificate, current.WrappingRevision)
		if err == nil {
			keys, err = vault.OpenEnrolledUserKeys(master, account.Binding, account.Envelope, *account.EnrollmentCertificate, *account.State, trust, current.Enrollment.ManifestRevision)
			if err == nil {
				advanced, e := next.AdvanceAccount(*account.State, account.Binding.Revision)
				if e != nil {
					keys.Wipe()
					keys = nil
					err = e
				} else {
					next = advanced
					if next.Revision > current.Revision {
						next.Revision = current.Revision + 1
					}
				}
			}
		}
	} else {
		if current.FormatVersion >= 5 || account.EnrollmentCertificate != nil || account.EncryptionCertificate == nil || account.SigningCertificate == nil {
			return nil, sharedpg.TrustState{}, sharedpg.ErrAdmissionResponse
		}
		next, err = current.AdvanceAccount(*account.State, account.Binding.Revision)
		if err == nil {
			keys, err = vault.OpenCurrentUserKeys(master, account.Binding, account.Envelope, *account.EncryptionCertificate, *account.SigningCertificate, *account.State, trust)
		}
		if err != nil {
			next = sharedpg.TrustState{}
		}
	}
	if err != nil {
		return nil, next, err
	}
	return keys, next, nil
}
