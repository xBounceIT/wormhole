package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSharedPreparedJoinDeviceDeletionRetry(t *testing.T) {
	j, f, p, source := preparedDeviceJoinFixture(t)
	pending, err := p.commit.PendingEnrollment(f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	j.preparation = &sharedJoinPreparation{options: f.o, pending: pending}
	device := &sharedJoinDeviceStorage{root: p.key, slots: p.slots, envelope: p.envelope}
	if err := j.stageDeviceLocked(f.o, device); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedTransportSetup(f.o, f.root, pending.Trust); err != nil {
		t.Fatal(err)
	}
	j.preparation.setupOwned = true
	if err := stageSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding, pending); err != nil {
		t.Fatal(err)
	}
	j.preparation.pendingOwned = true
	name, err := windows.UTF16PtrFromString(sharedDeviceEnrollmentPath(f.o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if handle != windows.InvalidHandle {
			windows.CloseHandle(handle)
		}
	}()
	if err := j.DiscardDevicePreparation(context.Background(), f.root, p.key); err != errSharedInvitationPreparationCleanup {
		t.Fatal(err)
	}
	for _, path := range []string{sharedTransportSetupPath(f.o.TrustPath), sharedPendingEnrollmentPath(f.o.TrustPath)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("partial cleanup", err)
		}
	}
	if j.preparation == nil || source.calls != 0 {
		t.Fatal("lost ownership or submitted during cleanup")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	handle = windows.InvalidHandle
	if err := j.DiscardDevicePreparation(context.Background(), f.root, p.key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sharedDeviceEnrollmentPath(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("device remains", err)
	}
}

func TestSharedInvitationPreparationDeletionRetry(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "setup", true: "intent"}[pending], func(t *testing.T) {
			join, f := invitationPreparationFixture(t)
			path := sharedTransportSetupPath(f.o.TrustPath)
			if pending {
				path = sharedPendingEnrollmentPath(f.o.TrustPath)
			}
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if handle != windows.InvalidHandle {
					windows.CloseHandle(handle)
				}
			}()
			if err := join.DiscardPreparation(context.Background(), f.root); err != errSharedInvitationPreparationCleanup {
				t.Fatal(err)
			}
			if err := windows.CloseHandle(handle); err != nil {
				t.Fatal(err)
			}
			handle = windows.InvalidHandle
			if err := join.DiscardPreparation(context.Background(), f.root); err != nil {
				t.Fatal("partial cleanup retry", err)
			}
		})
	}
}
