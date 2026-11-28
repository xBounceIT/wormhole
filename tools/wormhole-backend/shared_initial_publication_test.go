package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func initialPublicationFixture(t *testing.T, managed bool) (sharedAdmissionOptions, sharedJoinStartup, sharedStartupProtection) {
	o, p, protection, _, _ := initialPublicationAccountFixture(t, managed)
	return o, p, protection
}

func initialPublicationAccountFixture(t *testing.T, managed bool) (sharedAdmissionOptions, sharedJoinStartup, sharedStartupProtection, *recoveryFixture, *initialAccountPreparationProbe) {
	t.Helper()
	_, f, d, _, input, _ := initialJoinFixture(t)
	i, err := sharedpg.DecodeInvitation(input["invitation"].(string), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := d.commit.PendingEnrollment(f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	o := f.o
	o.Settings.DeviceRole = "wh_" + pending.RoleTag + "_d_" + o.Binding.DeviceID.String()
	o.Settings.Changes = sharedpg.ChangePolicy{TransactionPooler: true}
	if managed {
		o.Settings.TLSBundle = sharedTLSFixture(t, &o, pending.Trust, f.org, 1)
		pending, err = pending.ObserveTLS(o.Binding, o.Settings.TLSBundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	o.Settings, err = pending.ObservedTrust().PrepareTransport(o.Settings, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		t.Fatal(err)
	}
	p, err := makeRecoverableSharedJoinStartup(o, &sharedJoinDeviceStorage{root: d.key, slots: d.slots, envelope: d.envelope}, f.root, pending)
	if err != nil {
		t.Fatal(err)
	}
	p.Continuation, err = d.commit.SealContinuation(f.root, o.Binding, i)
	if err != nil {
		t.Fatal(err)
	}
	p.FormatVersion, p.Purpose = 3, "wormhole/shared-join-startup/v3"
	return o, p, startupTestProtection(), f, d
}

func TestSharedInitialPublicationCleanupFailureRetainsTheNativeOwner(t *testing.T) {
	h, _, prepared, _, input, _ := initialJoinFixture(t)
	move, remove := publishSharedInitialFile, removeSharedInitialEntry
	t.Cleanup(func() { publishSharedInitialFile, removeSharedInitialEntry = move, remove })
	publishSharedInitialFile = func(string, string) error { return errors.New("publication refused") }
	removeSharedInitialEntry = func(*os.Root, string) error { return errors.New("disk cleanup refused") }
	if _, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input)); err == nil {
		t.Fatal("publication failure admitted")
	}
	if h.shared == nil || h.shared.initial == nil || !h.closed || prepared.closed {
		t.Fatal("cleanup failure lost its owner or unlocked roots")
	}
	publication := h.shared.initial.coordinator.publication
	if publication == nil || publication.published {
		t.Fatal("unexpected publication state")
	}
	if _, err := os.Stat(publication.stage); err != nil {
		t.Fatal("lost pending cleanup", err)
	}
	publishSharedInitialFile, removeSharedInitialEntry = move, remove
	if err := h.Close(); err != nil {
		t.Fatal("cleanup retry failed", err)
	}
	if !prepared.closed {
		t.Fatal("successful cleanup retained roots")
	}
	if _, err := os.Stat(publication.stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup retry left staging", err)
	}
}

func TestSharedInitialPublicationPublishesWholeBoundBundleWithoutReplacement(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprint(managed), func(t *testing.T) {
			o, p, protection := initialPublicationFixture(t, managed)
			original := publishSharedInitialDirectory
			t.Cleanup(func() { publishSharedInitialDirectory = original })
			calls := 0
			publishSharedInitialDirectory = func(source, target string) error {
				calls++
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("shared directory appeared before complete publication")
				}
				for _, name := range []string{"device.trust.device", "device.trust.connection", "device.trust.enrollment", "device.trust.join-startup"} {
					if info, err := os.Stat(filepath.Join(source, name)); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
						t.Fatal("incomplete bundle reached publication", name, err)
					}
				}
				return original(source, target)
			}
			owned, err := publishSharedInitialBundle(context.Background(), o, p, protection)
			if err != nil || owned == nil || !owned.published || calls != 1 {
				t.Fatal("bundle not published", err, calls)
			}
			loaded, err := readSharedJoinStartup(o.TrustPath, protection)
			if err != nil || loaded.FormatVersion != 3 || !bytes.Equal(loaded.Continuation, p.Continuation) {
				t.Fatal("final-path snapshot failed", err)
			}
			if _, err := os.Lstat(owned.stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("staging alias retained")
			}
			if managed {
				if len(owned.directories) != 1 {
					t.Fatal("managed TLS cache omitted")
				}
				cache, err := sharedTLSCachePath(o.TrustPath, o.Settings.TLSBundle.Pin().Digest)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(cache)
				if err != nil || !bytes.Equal(raw, o.Settings.TLSBundle.Encode()) {
					t.Fatal("current signed bundle was not published", err)
				}
			}
			before, err := os.ReadFile(sharedJoinStartupPath(o.TrustPath))
			if err != nil {
				t.Fatal(err)
			}
			if other, err := publishSharedInitialBundle(context.Background(), o, p, protection); err == nil || other != nil {
				t.Fatal("existing shared state was replaced")
			}
			after, err := os.ReadFile(sharedJoinStartupPath(o.TrustPath))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("competing publication changed selection")
			}
			if err := owned.cleanup(); err != nil {
				t.Fatal("owned cleanup failed", err)
			}
			if err := owned.cleanup(); err != nil {
				t.Fatal("cleanup was not repeatable", err)
			}
		})
	}
}

type initialPublicationFileFault struct {
	sharedInitialFile
	mode string
}

func (f initialPublicationFileFault) Write(raw []byte) (int, error) {
	if f.mode == "write" {
		n, err := f.sharedInitialFile.Write(raw[:len(raw)/2])
		if err != nil {
			return n, err
		}
		return n, errors.New("partial write")
	}
	return f.sharedInitialFile.Write(raw)
}
func (f initialPublicationFileFault) Sync() error {
	if f.mode == "sync" {
		return errors.New("file sync")
	}
	return f.sharedInitialFile.Sync()
}
func (f initialPublicationFileFault) Close() error {
	err := f.sharedInitialFile.Close()
	if f.mode == "close" {
		return errors.New("file close")
	}
	return err
}

func TestSharedInitialPublicationDoesNotPublishAnyPartialWrite(t *testing.T) {
	for _, mode := range []string{"open", "write", "sync", "close"} {
		for position := 1; position <= 4; position++ {
			t.Run(fmt.Sprintf("%s-%d", mode, position), func(t *testing.T) {
				o, p, protection := initialPublicationFixture(t, false)
				original := openSharedInitialFile
				t.Cleanup(func() { openSharedInitialFile = original })
				calls := 0
				openSharedInitialFile = func(root *os.Root, name string) (sharedInitialFile, error) {
					calls++
					if calls == position && mode == "open" {
						return nil, errors.New("file open")
					}
					f, err := original(root, name)
					if err != nil {
						return nil, err
					}
					if calls == position {
						return initialPublicationFileFault{f, mode}, nil
					}
					return f, nil
				}
				owned, err := publishSharedInitialBundle(context.Background(), o, p, protection)
				if err == nil || owned == nil || owned.published {
					t.Fatal("partial bundle published", err)
				}
				if _, err := os.Lstat(owned.target); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("partial shared marker escaped")
				}
				openSharedInitialFile = original
				if err := owned.cleanup(); err != nil {
					t.Fatal("known partial bytes could not be cleaned", err)
				}
			})
		}
	}
}

func TestSharedInitialPublicationPreservesUnknownOrReplacedFiles(t *testing.T) {
	for _, mode := range []string{"unknown", "changed", "same-length", "replacement", "directory", "cache-extra", "cache-replaced"} {
		t.Run(mode, func(t *testing.T) {
			o, p, protection := initialPublicationFixture(t, mode == "cache-extra" || mode == "cache-replaced")
			owned, err := publishSharedInitialBundle(context.Background(), o, p, protection)
			if err != nil {
				t.Fatal(err)
			}
			var path string
			sentinel := []byte("preserve external change")
			switch mode {
			case "unknown":
				path = filepath.Join(owned.target, "foreign")
			case "changed":
				path = sharedDeviceEnrollmentPath(o.TrustPath)
			case "same-length":
				path = sharedDeviceEnrollmentPath(o.TrustPath)
				sentinel = bytes.Clone(p.DeviceFile)
				sentinel[len(sentinel)-1] ^= 1
			case "replacement":
				path = sharedDeviceEnrollmentPath(o.TrustPath)
				if err := os.Rename(path, owned.target+".device-original"); err != nil {
					t.Fatal(err)
				}
				sentinel = p.DeviceFile
			case "directory":
				if err := os.Rename(owned.target, owned.target+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(owned.target, 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(owned.target, "foreign")
			case "cache-extra":
				path = filepath.Join(owned.target, "device.trust.tls", "foreign")
			case "cache-replaced":
				dir := filepath.Join(owned.target, "device.trust.tls")
				if err := os.Rename(dir, owned.target+".cache-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "foreign")
			}
			if err := os.WriteFile(path, sentinel, 0600); err != nil {
				t.Fatal(err)
			}
			if err := owned.cleanup(); err == nil {
				t.Fatal("unknown state erased", mode)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, sentinel) {
				t.Fatal("external state changed", mode, err)
			}
		})
	}
}

func TestSharedInitialPublicationSyncAndRenameOutcomes(t *testing.T) {
	for _, mode := range []string{"stage-sync", "parent-sync", "rename", "uncertain-rename", "competing-target", "cancel-before-rename"} {
		t.Run(mode, func(t *testing.T) {
			o, p, protection := initialPublicationFixture(t, false)
			originalSync, originalMove := privateFileDirectorySync, publishSharedInitialDirectory
			t.Cleanup(func() { privateFileDirectorySync = originalSync; publishSharedInitialDirectory = originalMove })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			privateFileDirectorySync = func(path string) error {
				if mode == "stage-sync" && filepath.Base(path) != "." && filepath.Dir(path) == filepath.Dir(filepath.Dir(o.TrustPath)) {
					return errors.New("stage sync")
				}
				if mode == "parent-sync" && path == filepath.Dir(filepath.Dir(o.TrustPath)) {
					return errors.New("parent sync")
				}
				if mode == "cancel-before-rename" {
					cancel()
				}
				return originalSync(path)
			}
			publishSharedInitialDirectory = func(source, target string) error {
				if mode == "rename" {
					return errors.New("rename refused")
				}
				if mode == "competing-target" {
					if err := os.Mkdir(target, 0700); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(target, "foreign"), []byte("preserve"), 0600); err != nil {
						return err
					}
				}
				err := originalMove(source, target)
				if err == nil && mode == "uncertain-rename" {
					return errors.New("rename acknowledgement lost")
				}
				return err
			}
			owned, err := publishSharedInitialBundle(ctx, o, p, protection)
			if err == nil || owned == nil {
				t.Fatal("failed publication acknowledged", mode, err)
			}
			if (mode == "parent-sync" || mode == "uncertain-rename") != owned.published {
				t.Fatal("lost publication ownership", mode, owned.published)
			}
			privateFileDirectorySync, publishSharedInitialDirectory = originalSync, originalMove
			if err := owned.cleanup(); err != nil {
				t.Fatal("publication cleanup retry failed", mode, err)
			}
			if mode == "competing-target" {
				if raw, err := os.ReadFile(filepath.Join(filepath.Dir(o.TrustPath), "foreign")); err != nil || string(raw) != "preserve" {
					t.Fatal("competing target erased")
				}
			}
		})
	}
}

func TestSharedInitialPublicationRejectsInvalidSelectionBeforeStaging(t *testing.T) {
	o, p, protection := initialPublicationFixture(t, false)
	for _, mode := range []string{"nil", "canceled", "v2", "path", "protect"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			options, value, guard := o, p, protection
			switch mode {
			case "nil":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "v2":
				value.FormatVersion = 2
			case "path":
				options.TrustPath = "relative"
			case "protect":
				guard.protect = nil
			}
			if owned, err := publishSharedInitialBundle(ctx, options, value, guard); err == nil || owned != nil {
				t.Fatal("invalid selection started publication", mode, err)
			}
		})
	}
	var absent *sharedInitialPublication
	if err := absent.cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := absent.open(); err == nil {
		t.Fatal("missing owner opened")
	}
}

func TestSharedInitialPublicationCleanupFailureRequiresConfirmedRetry(t *testing.T) {
	for _, mode := range []string{"file", "lock", "cache-directory", "sync", "late-file", "replaced-directory"} {
		t.Run(mode, func(t *testing.T) {
			o, p, protection := initialPublicationFixture(t, mode == "cache-directory")
			owned, err := publishSharedInitialBundle(context.Background(), o, p, protection)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(owned.target, "device.trust.lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			originalRemove, originalSync := removeSharedInitialEntry, privateFileDirectorySync
			t.Cleanup(func() { removeSharedInitialEntry = originalRemove; privateFileDirectorySync = originalSync })
			triggered := false
			replacementBlocked := false
			removeSharedInitialEntry = func(root *os.Root, name string) error {
				if !triggered && (mode == "file" && name == "device.trust.device" || mode == "lock" && name == "device.trust.lock" || mode == "cache-directory" && name == "device.trust.tls") {
					triggered = true
					return errors.New("remove unavailable")
				}
				err := originalRemove(root, name)
				if !triggered && mode == "late-file" {
					triggered = true
					return root.WriteFile("new-external-file", []byte("preserve"), 0600)
				}
				if !triggered && mode == "replaced-directory" {
					triggered = true
					if err := os.Rename(owned.target, owned.target+".original"); err != nil {
						replacementBlocked = true
						return err
					}
					if err := os.Mkdir(owned.target, 0700); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(owned.target, "new-external-file"), []byte("preserve"), 0600); err != nil {
						return err
					}
				}
				return err
			}
			privateFileDirectorySync = func(path string) error {
				if mode == "sync" && !triggered {
					triggered = true
					return errors.New("directory sync unavailable")
				}
				return originalSync(path)
			}
			if err := owned.cleanup(); err == nil || !triggered {
				t.Fatal("unconfirmed cleanup acknowledged", mode, err)
			}
			removeSharedInitialEntry, privateFileDirectorySync = originalRemove, originalSync
			if replacementBlocked {
				actual, err := captureInitialJoinDirectory(owned.target)
				if err != nil || !os.SameFile(actual, owned.directory) {
					t.Fatal("blocked rename changed directory identity", err)
				}
				if err := owned.cleanup(); err != nil {
					t.Fatal("cleanup after OS-blocked directory replacement", err)
				}
				return
			}
			if mode == "late-file" || mode == "replaced-directory" {
				path := filepath.Join(owned.target, "new-external-file")
				if raw, err := os.ReadFile(path); err != nil || string(raw) != "preserve" {
					t.Fatal("late external file erased", err)
				}
				if err := owned.cleanup(); err == nil {
					t.Fatal("retry adopted external files")
				}
				return
			}
			if err := owned.cleanup(); err != nil {
				t.Fatal("owned retry failed", mode, err)
			}
		})
	}
}

func TestInitialJoinAtomicPublicationRefusesReplacedParentBeforeDiscard(t *testing.T) {
	h, f, _, session, input, _ := initialJoinFixture(t)
	original := publishSharedInitialDirectory
	t.Cleanup(func() { publishSharedInitialDirectory = original })
	var target string
	publishSharedInitialDirectory = func(source, destination string) error {
		if err := original(source, destination); err != nil {
			return err
		}
		target = destination
		if err := os.Rename(target, target+".original"); err != nil {
			return err
		}
		if err := os.Mkdir(target, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, "foreign"), []byte("preserve"), 0600)
	}
	if raw, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input)); err == nil || len(raw) != 0 || session.calls != 0 {
		t.Fatal("replaced parent reached SQL", err, session.calls)
	}
	if raw, err := os.ReadFile(filepath.Join(target, "foreign")); err != nil || string(raw) != "preserve" {
		t.Fatal("replacement was erased", err)
	}
	if !h.closed || h.shared == nil {
		t.Fatal("unconfirmed cleanup released workspace")
	}
	publishSharedInitialDirectory = original
	if err := os.Remove(filepath.Join(target, "foreign")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target+".original", target); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal("restored owner cleanup", err)
	}
	if _, err := os.Lstat(filepath.Dir(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed cleanup left shared marker", err)
	}
}

func TestSharedInitialFilePublicationDoesNotReplaceOrForgetUncertainRename(t *testing.T) {
	for _, mode := range []string{"refused", "uncertain", "competing"} {
		t.Run(mode, func(t *testing.T) {
			o, p, protection := initialPublicationFixture(t, false)
			original := publishSharedInitialFile
			t.Cleanup(func() { publishSharedInitialFile = original })
			var competing string
			publishSharedInitialFile = func(source, target string) error {
				if mode == "refused" {
					return errors.New("file rename refused")
				}
				if mode == "competing" {
					competing = target
					if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
						return err
					}
				}
				err := original(source, target)
				if err == nil && mode == "uncertain" {
					return errors.New("rename acknowledgement lost")
				}
				return err
			}
			owned, err := publishSharedInitialBundle(context.Background(), o, p, protection)
			if err == nil || owned == nil || owned.published {
				t.Fatal("file publication error exposed shared state", err)
			}
			publishSharedInitialFile = original
			if mode == "competing" {
				if err := owned.cleanup(); err == nil {
					t.Fatal("competing file was adopted")
				}
				if raw, err := os.ReadFile(competing); err != nil || string(raw) != "preserve" {
					t.Fatal("competing file overwritten", err)
				}
				if err := os.Remove(competing); err != nil {
					t.Fatal(err)
				}
			}
			if err := owned.cleanup(); err != nil {
				t.Fatal("owned file rename cleanup", mode, err)
			}
		})
	}
}
