package main

import (
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSharedEnrollmentCleanupLockedJournal(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	proof := enrollmentPublicationProof(t, b, p)
	if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(sharedPendingEnrollmentPath(path))
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
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != errSharedEnrollmentCleanup {
		t.Fatal("locked journal cleanup", err)
	}
	if _, err := os.Stat(sharedPendingEnrollmentPath(path)); err != nil {
		t.Fatal("journal vanished", err)
	}
	if _, err := readActiveSharedTrustFile(path, root, b, 1); err != errSharedEnrollmentPending {
		t.Fatal("cleanup failure admitted", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	handle = windows.InvalidHandle
	if err := promoteSharedEnrollment(path, root, b, p, proof); err != nil {
		t.Fatal(err)
	}
	current, err := readActiveSharedTrustFile(path, root, b, 1)
	if err != nil || !reflect.DeepEqual(current, proof.target) {
		t.Fatal(err)
	}
}
