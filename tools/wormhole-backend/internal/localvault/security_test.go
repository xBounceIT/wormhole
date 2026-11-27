package localvault

import (
	"bytes"
	"context"
	"errors"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

func TestLocalSecurityRequiresEffectiveFloorAndCompatibleSlots(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*vault.LocalPolicy, *vault.SlotFile)
		os     vault.Profile
		want   error
	}{
		{"default-recovery", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots = nil }, vault.Default, nil},
		{"standard", func(p *vault.LocalPolicy, s *vault.SlotFile) {}, vault.Standard, nil},
		{"default-unprotected", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots = []vault.Slot{{Kind: vault.SlotUnprotected}} }, vault.Default, nil},
		{"standard-unprotected", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots = []vault.Slot{{Kind: vault.SlotUnprotected}} }, vault.Standard, vault.ErrPolicy},
		{"default-mixed-unprotected", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			s.Slots = append(s.Slots, vault.Slot{Kind: vault.SlotUnprotected})
		}, vault.Default, vault.ErrPolicy},
		{"standard-mixed-unprotected", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			s.Slots = append(s.Slots, vault.Slot{Kind: vault.SlotUnprotected})
		}, vault.Standard, vault.ErrPolicy},
		{"unprotected-ask", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			s.Slots = []vault.Slot{{Kind: vault.SlotUnprotected}}
			p.Policy.ASKRequired = true
		}, vault.Default, vault.ErrPolicy},
		{"standard-no-recovery", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots = s.Slots[:1] }, vault.Standard, vault.ErrPolicy},
		{"standard-recovery-only", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots = []vault.Slot{{Kind: vault.SlotRecovery}} }, vault.Standard, vault.ErrPolicy},
		{"hardened", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			p.Policy.KDF = vault.KDFV2
			s.Slots[0].Preset = vault.KDFV2
		}, vault.Hardened, vault.ErrPolicy},
		{"paranoid", func(p *vault.LocalPolicy, s *vault.SlotFile) { p.Policy.KDF = vault.KDFV3; p.Policy.ASKRequired = true }, vault.Paranoid, vault.ErrPolicy},
		{"unknown-floor", func(p *vault.LocalPolicy, s *vault.SlotFile) {}, "future", vault.ErrPolicy},
		{"low-standard", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			p.Policy.KDF = vault.KDFLow
			p.Policy.LowKDFApproved = true
		}, vault.Standard, vault.ErrPolicy},
		{"weak-slot", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots[0].Preset = vault.KDFLow }, vault.Default, vault.ErrPolicy},
		{"unknown-slot", func(p *vault.LocalPolicy, s *vault.SlotFile) { s.Slots[0].Preset = "future" }, vault.Default, vault.ErrPolicy},
		{"ask-missing", func(p *vault.LocalPolicy, s *vault.SlotFile) { p.Policy.ASKRequired = true }, vault.Default, vault.ErrPolicy},
		{"ask-present", func(p *vault.LocalPolicy, s *vault.SlotFile) {
			p.Policy.ASKRequired = true
			s.Slots[0].ASKRequired = true
		}, vault.Default, nil},
		{"api-future", func(p *vault.LocalPolicy, s *vault.SlotFile) { p.Policy.MinAPI = 2; p.Policy.MaxAPI = 2 }, vault.Default, vault.ErrNewerFormat},
		{"api-old", func(p *vault.LocalPolicy, s *vault.SlotFile) { p.Policy.MaxAPI = 0 }, vault.Default, vault.ErrNewerFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := vault.LocalPolicy{Policy: vault.Policy{FormatVersion: 1, WorkspaceID: "workspace", Sequence: 1, Profile: vault.Default, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, UserProfile: vault.Default}
			s := vault.SlotFile{Slots: []vault.Slot{{Kind: vault.SlotPassword, Preset: vault.KDFV1}, {Kind: vault.SlotRecovery}}}
			test.change(&p, &s)
			if err := validateLocalSecurity(p, s, test.os); err != test.want {
				t.Fatal(err, test.want)
			}
		})
	}
}

func TestLocalSecurityProjectionAndReopenGate(t *testing.T) {
	profiles := []vault.Profile{vault.Default, vault.Standard, vault.Hardened, vault.Paranoid}
	for w, workspace := range profiles {
		for u, user := range profiles {
			for o, os := range profiles {
				p := vault.LocalPolicy{Policy: vault.Policy{Profile: workspace, Sequence: 7}, UserProfile: user}
				got := ResolveSecurityProfile(p.Policy, p.UserProfile, os)
				want := profiles[max(w, u, o)]
				source := "workspace"
				if o > 0 && o >= w && o >= u {
					source = "os"
				} else if u > w {
					source = "user"
				}
				if got.Effective != want || got.Source != source || got.Sequence != 7 || got.Workspace != workspace || got.User != user || got.OS != os {
					t.Fatal("incorrect authority")
				}
			}
		}
	}
	ctx := context.Background()
	o, path, opts, key := owner(t)
	if p, err := o.ReadSecurityProfile(ctx); err != nil || p.Effective != vault.Default || p.Sequence != 1 {
		t.Fatal(p, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadSecurityProfile(canceled); err != context.Canceled {
		t.Fatal(err)
	}
	p, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	p.Policy.MinAPI = 2
	p.Policy.MaxAPI = 2
	if _, err = o.PutLocalPolicy(ctx, p.Policy, vault.Default, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ReadSecurityProfile(ctx); err != vault.ErrNewerFormat {
		t.Fatal(err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ReadSecurityProfile(ctx); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	opts.Create = false
	input := bytes.Clone(key)
	if reopened, err := Open(ctx, path, opts, input); !errors.Is(err, vault.ErrNewerFormat) || reopened != nil {
		t.Fatal("unsupported API opened", err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("key retained")
	}
}

func TestProtectionRequiresAuthenticatedLivePolicy(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	if protected, err := o.ReadProtection(ctx); err != nil || !protected {
		t.Fatal(protected, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadProtection(cancelled); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadProtection(ctx); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestRetainedLocalProfileRechecksSlotsAndKDF(t *testing.T) {
	p := vault.LocalPolicy{Policy: vault.Policy{FormatVersion: 1, WorkspaceID: "workspace", Sequence: 1, Profile: vault.Default, KDF: vault.KDFV1, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, UserProfile: vault.Default}
	slots := vault.SlotFile{Slots: []vault.Slot{{Kind: vault.SlotPassword, Preset: vault.KDFV1}, {Kind: vault.SlotRecovery}}}
	o := &Owner{}
	if _, err := o.applySecurityProfile(p, slots, vault.Standard); err != nil {
		t.Fatal(err)
	}
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.checkSecurityProfile(stopped, p, slots); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled machine policy read", err)
	}
	if _, err := o.applySecurityProfile(p, vault.SlotFile{Slots: slots.Slots[1:]}, vault.Default); err != vault.ErrPolicy {
		t.Fatal("retained floor accepted a recovery-only slot file", err)
	}
	low := p
	low.Policy.KDF, low.Policy.LowKDFApproved = vault.KDFLow, true
	if _, err := o.applySecurityProfile(low, slots, vault.Default); err != vault.ErrPolicy {
		t.Fatal("retained floor accepted kdf-low", err)
	}
	got, err := o.applySecurityProfile(p, slots, vault.Default)
	if err != nil || got.Effective != vault.Standard || got.Source != "os" || !got.RetainedUntilLock {
		t.Fatal(got, err)
	}
	p.UserProfile = vault.Standard
	got, err = o.applySecurityProfile(p, slots, vault.Default)
	if err != nil || got.Effective != vault.Standard || got.Source != "user" || got.RetainedUntilLock {
		t.Fatal(got, err)
	}
}
