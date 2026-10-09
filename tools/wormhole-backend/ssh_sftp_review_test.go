package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestSftpCopyCancellationPreservesDestination(t *testing.T) {
	for _, direction := range []string{"local-to-local", "local-to-remote", "remote-to-local"} {
		t.Run(direction, func(t *testing.T) {
			client := newSftpTestClient(t)
			root := t.TempDir()
			source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
			if err := os.WriteFile(source, []byte("incoming"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, []byte("existing"), 0o644); err != nil {
				t.Fatal(err)
			}
			plan := sshSftpTransferPlan{sourcePath: source, destinationPath: destination, overwrite: true}
			if direction == "local-to-remote" {
				plan.destinationPath = sftpTestPath(destination)
			}
			if direction == "remote-to-local" {
				plan.sourcePath = sftpTestPath(source)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := copyTransferFile(ctx, client, direction, plan, func(int64) { t.Fatal("cancelled copy published progress") }); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled copy error = %v", err)
			}
			contents, err := os.ReadFile(destination)
			if err != nil || string(contents) != "existing" {
				t.Fatalf("cancelled copy damaged destination: %q, %v", contents, err)
			}
		})
	}
}

func TestSftpCopyRequiresOverwritePermission(t *testing.T) {
	for _, direction := range []string{"local-to-local", "local-to-remote", "remote-to-local"} {
		t.Run(direction, func(t *testing.T) {
			client := newSftpTestClient(t)
			root := t.TempDir()
			source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
			if err := os.WriteFile(source, []byte("incoming"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, []byte("appeared after preflight"), 0o644); err != nil {
				t.Fatal(err)
			}
			plan := sshSftpTransferPlan{sourcePath: source, destinationPath: destination}
			if direction == "local-to-remote" {
				plan.destinationPath = sftpTestPath(destination)
			}
			if direction == "remote-to-local" {
				plan.sourcePath = sftpTestPath(source)
			}
			if err := copyTransferFile(context.Background(), client, direction, plan, func(int64) {}); err == nil {
				t.Fatal("unapproved overwrite succeeded")
			}
			contents, err := os.ReadFile(destination)
			if err != nil || string(contents) != "appeared after preflight" {
				t.Fatalf("unapproved overwrite damaged destination: %q, %v", contents, err)
			}
		})
	}
}

func TestSftpRenameRejectsOccupiedName(t *testing.T) {
	for _, pane := range []string{"local", "remote"} {
		t.Run(pane, func(t *testing.T) {
			native := &sshNativeSession{sftpClient: newSftpTestClient(t)}
			root := t.TempDir()
			source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
			if err := os.WriteFile(source, []byte("source"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destination, []byte("destination"), 0o644); err != nil {
				t.Fatal(err)
			}
			command := sshWireCommand{Pane: pane, Operation: "rename", Path: source, DestinationPath: destination}
			if pane == "remote" {
				command.Path, command.DestinationPath = sftpTestPath(source), sftpTestPath(destination)
			}
			if err := native.runSftpOperation(command); err == nil {
				t.Fatal("rename silently replaced an occupied name")
			}
			for path, expected := range map[string]string{source: "source", destination: "destination"} {
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != expected {
					t.Fatalf("rename damaged %q: %q, %v", path, contents, err)
				}
			}
		})
	}
}

func TestSftpQueuedOperationCannotMutateReopenedBrowser(t *testing.T) {
	server, native, output := newLocalTransferTestServer()
	native.sftpClient, native.sftpGeneration = newSftpTestClient(t), 1
	file := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	native.sftpTransferMu.Lock()
	server.sftpOperation(sshWireCommand{SessionID: native.id, RequestID: "old-delete", Pane: "remote", Operation: "delete", Path: sftpTestPath(file)})
	native.closeSftp(false)
	native.sftpMu.Lock()
	native.sftpClient = newSftpTestClient(t)
	native.sftpMu.Unlock()
	native.startSftpOpen("reopened")
	native.sftpTransferMu.Unlock()
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.RequestID == "old-delete" })
	if event.Error == "" {
		t.Fatal("stale delete ran on the reopened browser")
	}
	contents, err := os.ReadFile(file)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("stale operation damaged file: %q, %v", contents, err)
	}
}

func TestSftpPlansCannotExceedIpcPathBounds(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	command := sshWireCommand{Direction: "local-to-remote", DestinationPath: "/" + strings.Repeat("a", sshSftpMaxPathBytes-1), Items: []sshSftpTransferItem{{SourcePath: source, Name: "source"}}}
	if _, err := buildSftpTransferPlans(nil, command, context.Background()); err == nil {
		t.Fatal("transfer plan exceeded the destination IPC bound")
	}
}

func TestSftpDirectorySymlinkReplacementNeedsConfirmation(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(destination, "folder")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	server, native, output := newLocalTransferTestServer()
	server.sftpTransfer(sshWireCommand{SessionID: native.id, TransferID: "directory-link", Direction: "local-to-local", DestinationPath: destination, Items: []sshSftpTransferItem{{SourcePath: source, Name: "folder", IsDirectory: true}}})
	t.Cleanup(func() { server.cancelTransfersForSession(native.id); server.transferWG.Wait() })
	event := waitSftpTestEvent(t, output, func(event sshWireEvent) bool {
		return event.Type == "sftp.conflict" || strings.HasPrefix(event.TransferState, "batch-")
	})
	if event.Type != "sftp.conflict" {
		t.Fatalf("symlink replaced without a warning: %#v", event)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink changed before confirmation: %v", err)
	}
	server.sftpTransferDecision(sshWireCommand{SessionID: native.id, TransferID: "directory-link", ItemID: event.ItemID, Decision: "skip"})
	waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.TransferState == "batch-completed" })
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("skipped symlink changed: %v", err)
	}
}

func TestSftpSkippedDirectoryDoesNotCopyDescendants(t *testing.T) {
	for _, direction := range []string{"local-to-local", "local-to-remote", "remote-to-local"} {
		t.Run(direction, func(t *testing.T) {
			client := newSftpTestClient(t)
			root := t.TempDir()
			source, destination, outside := filepath.Join(root, "source"), filepath.Join(root, "destination"), filepath.Join(root, "outside")
			for _, directory := range []string{source, destination, outside} {
				if err := os.Mkdir(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(source, "new.txt"), []byte("incoming"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(destination, "folder")); err != nil {
				t.Skipf("symbolic links unavailable: %v", err)
			}
			server, native, output := newLocalTransferTestServer()
			native.sftpClient = client
			command := sshWireCommand{SessionID: native.id, TransferID: "skip-folder", Direction: direction, DestinationPath: destination, Items: []sshSftpTransferItem{
				{SourcePath: source, Name: "folder", IsDirectory: true},
				{SourcePath: filepath.Join(source, "new.txt"), Name: "sibling.txt"},
			}}
			if direction == "local-to-remote" {
				command.DestinationPath = sftpTestPath(destination)
			}
			if direction == "remote-to-local" {
				for index := range command.Items {
					command.Items[index].SourcePath = sftpTestPath(command.Items[index].SourcePath)
				}
			}
			server.sftpTransfer(command)
			t.Cleanup(func() { server.cancelTransfersForSession(native.id); server.transferWG.Wait() })
			conflict := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return event.Type == "sftp.conflict" })
			server.sftpTransferDecision(sshWireCommand{SessionID: native.id, TransferID: command.TransferID, ItemID: conflict.ItemID, Decision: "skip"})
			terminal := waitSftpTestEvent(t, output, func(event sshWireEvent) bool { return strings.HasPrefix(event.TransferState, "batch-") })
			if terminal.TransferState != "batch-completed" {
				t.Fatalf("skipping folder aborted later items: %#v", terminal)
			}
			if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
				t.Fatalf("skipped folder still copied descendants: %v", err)
			}
			contents, err := os.ReadFile(filepath.Join(destination, "sibling.txt"))
			if err != nil || string(contents) != "incoming" {
				t.Fatalf("later item was lost: %q, %v", contents, err)
			}
		})
	}
}

func TestSftpCopyCannotTruncateHardLinkedSource(t *testing.T) {
	root := t.TempDir()
	source, alias := filepath.Join(root, "source"), filepath.Join(root, "alias")
	if err := os.WriteFile(source, []byte("preserve source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	plan := sshSftpTransferPlan{sourcePath: source, destinationPath: alias, overwrite: true}
	if err := copyTransferFile(context.Background(), nil, "local-to-local", plan, func(int64) {}); err == nil {
		t.Fatal("copy accepted an alias of its source")
	}
	contents, err := os.ReadFile(source)
	if err != nil || string(contents) != "preserve source" {
		t.Fatalf("copy truncated its hard-linked source: %q, %v", contents, err)
	}
}

func TestSftpRenameCannotReplaceAliasOfSource(t *testing.T) {
	root := t.TempDir()
	source, alias := filepath.Join(root, "source"), filepath.Join(root, "alias")
	if err := os.WriteFile(source, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	native := &sshNativeSession{}
	if err := native.runSftpOperation(sshWireCommand{Pane: "local", Operation: "rename", Path: source, DestinationPath: alias}); err == nil {
		t.Fatal("rename replaced an occupied alias without a warning")
	}
}

func TestSftpLocalRenamePreservesCaseOnlyChanges(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "report.txt")
	if err := os.WriteFile(source, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !sameLocalRenameEntry(source, source) {
		t.Fatal("identical path was not recognized as the same entry")
	}
	destination := filepath.Join(root, "Report.txt")
	if err := (&sshNativeSession{}).runSftpOperation(sshWireCommand{Pane: "local", Operation: "rename", Path: source, DestinationPath: destination}); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "Report.txt" {
		t.Fatalf("renamed entries = %v, %v", entries, err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("case-only rename damaged contents: %q, %v", contents, err)
	}
}

func TestSftpLocalRenameRecognizesSameEntryThroughParentAlias(t *testing.T) {
	root := t.TempDir()
	parent, alias := filepath.Join(root, "parent"), filepath.Join(root, "alias")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	source := filepath.Join(parent, "report.txt")
	if err := os.WriteFile(source, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	name := "Report.txt"
	if _, err := os.Lstat(filepath.Join(parent, name)); os.IsNotExist(err) {
		name = "report.txt" // Case-sensitive volumes still expose the same entry via the parent alias.
	}
	destination := filepath.Join(alias, name)
	if err := (&sshNativeSession{}).runSftpOperation(sshWireCommand{Pane: "local", Operation: "rename", Path: source, DestinationPath: destination}); err != nil {
		t.Fatalf("same-entry rename through directory alias: %v", err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("same-entry rename damaged contents: %q, %v", contents, err)
	}
}

func TestSftpLocalRenameRejectsSameNamedHardLinkInDifferentParent(t *testing.T) {
	root := t.TempDir()
	parent, other := filepath.Join(root, "parent"), filepath.Join(root, "other")
	for _, directory := range []string{parent, other} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	source, destination := filepath.Join(parent, "report.txt"), filepath.Join(other, "report.txt")
	if err := os.WriteFile(source, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, destination); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := (&sshNativeSession{}).runSftpOperation(sshWireCommand{Pane: "local", Operation: "rename", Path: source, DestinationPath: destination}); err == nil {
		t.Fatal("same-named hard link was mistaken for the same directory entry")
	}
	for _, path := range []string{source, destination} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != "keep" {
			t.Fatalf("refused rename changed %s: %q, %v", path, contents, err)
		}
	}
}

func TestSftpRemoteRenamePreservesCaseOnlyChanges(t *testing.T) {
	client := newSftpTestClient(t)
	native := &sshNativeSession{sftpClient: client}
	root := t.TempDir()
	source, destination := filepath.Join(root, "report.txt"), filepath.Join(root, "Report.txt")
	if err := os.WriteFile(source, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := native.runSftpOperation(sshWireCommand{Pane: "remote", Operation: "rename", Path: sftpTestPath(source), DestinationPath: sftpTestPath(destination)}); err != nil {
		t.Fatalf("remote case-only rename: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "Report.txt" {
		t.Fatalf("remote renamed entries = %v, %v", entries, err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("remote case-only rename damaged contents: %q, %v", contents, err)
	}
}

func TestSftpRemoteRenameEntryCheckFailsClosed(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		names   []string
		listErr error
		want    bool
	}{
		{name: "single entry", names: []string{"other.txt", "report.txt"}, want: true},
		{name: "distinct case-sensitive entries", names: []string{"report.txt", "Report.txt"}},
		{name: "missing entry", names: []string{"other.txt"}},
		{name: "listing failure", listErr: os.ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			var listings atomic.Int32
			client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(*sftp.Request) (sftp.ListerAt, error) {
				listings.Add(1)
				entries := sftpReviewLister{}
				for _, name := range test.names {
					entries = append(entries, sftpReviewNamedInfo{FileInfo: info, name: name})
				}
				return entries, test.listErr
			})})
			if !sameRemoteRenameEntry(client, "/dir/report.txt", "/dir/report.txt") {
				t.Fatal("identical remote path was not recognized")
			}
			for _, destination := range []string{"/dir/other.txt", "/other/Report.txt"} {
				if sameRemoteRenameEntry(client, "/dir/report.txt", destination) {
					t.Fatalf("different remote entry was accepted: %s", destination)
				}
			}
			if listings.Load() != 0 {
				t.Fatal("ordinary rename unexpectedly read the remote directory")
			}
			if got := sameRemoteRenameEntry(client, "/dir/report.txt", "/dir/Report.txt"); got != test.want {
				t.Fatalf("remote entry identity = %v, want %v", got, test.want)
			}
		})
	}
}

type sftpReviewReader func(*sftp.Request) (io.ReaderAt, error)

func (reader sftpReviewReader) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	return reader(request)
}

type sftpReviewWriter func(*sftp.Request) (io.WriterAt, error)

func (writer sftpReviewWriter) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	return writer(request)
}

type sftpReviewCloseFailure struct{}

func (sftpReviewCloseFailure) WriteAt(data []byte, _ int64) (int, error) { return len(data), nil }
func (sftpReviewCloseFailure) Close() error                              { return errors.New("remote destination close failed") }

func newSftpReviewRequestClient(t *testing.T, handlers sftp.Handlers) *sftp.Client {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	server := sftp.NewRequestServer(serverConnection, handlers)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	client, err := sftp.NewClientPipe(clientConnection, clientConnection)
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("SFTP request fixture did not stop")
		}
	})
	return client
}

func TestSftpCancellationDuringRemoteOpenPreservesDestination(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("incoming"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("preserved"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileGet: sftpReviewReader(func(*sftp.Request) (io.ReaderAt, error) {
		cancel()
		return os.Open(source)
	})})
	err := copyTransferFile(ctx, client, "remote-to-local", sshSftpTransferPlan{
		sourcePath: "/source", destinationPath: destination, overwrite: true,
	}, func(int64) { t.Fatal("cancelled download published progress") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "preserved" {
		t.Fatalf("cancel during remote open damaged destination: %q, %v", contents, err)
	}
}

func TestSftpCopyReportsRemoteCloseFailure(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("incoming"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := newSftpReviewRequestClient(t, sftp.Handlers{FilePut: sftpReviewWriter(func(*sftp.Request) (io.WriterAt, error) { return sftpReviewCloseFailure{}, nil })})
	err := copyTransferFile(context.Background(), client, "local-to-remote", sshSftpTransferPlan{
		sourcePath: source, destinationPath: "/destination",
	}, func(int64) {})
	if err == nil {
		t.Fatal("remote close failure was reported as a successful transfer")
	}
}

type sftpReviewFileList func(*sftp.Request) (sftp.ListerAt, error)

func (list sftpReviewFileList) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	return list(request)
}

type sftpReviewNamedInfo struct {
	os.FileInfo
	name string
}

func (info sftpReviewNamedInfo) Name() string { return info.name }

type sftpReviewLister []os.FileInfo

func (list sftpReviewLister) ListAt(files []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(list)) {
		return 0, io.EOF
	}
	count := copy(files, list[offset:])
	if int(offset)+count == len(list) {
		return count, io.EOF
	}
	return count, nil
}

func TestSftpRejectsOverlongPlanBeforeRecursing(t *testing.T) {
	directory, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var listings atomic.Int32
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
		if request.Method == "List" && listings.Add(1) > 1 {
			return nil, errors.New("walk read an already out-of-bounds path")
		}
		return sftpReviewLister{sftpReviewNamedInfo{FileInfo: directory, name: strings.Repeat("d", sshSftpMaxNameBytes)}}, nil
	})})
	command := sshWireCommand{Direction: "remote-to-local", DestinationPath: t.TempDir(), Items: []sshSftpTransferItem{{SourcePath: "/root", Name: strings.Repeat("r", sshSftpMaxNameBytes)}}}
	if _, err := buildSftpTransferPlans(client, command, context.Background()); err == nil {
		t.Fatal("overlong recursive plan was accepted")
	}
	if listings.Load() != 1 {
		t.Fatalf("unsafe path was traversed before validation: %d listings", listings.Load())
	}
}

func TestSftpPlanningRejectsInvalidAndUnavailableSources(t *testing.T) {
	client := newSftpTestClient(t)
	for _, direction := range []string{"local-to-local", "remote-to-local"} {
		for _, source := range []string{"relative", "/missing-sftp-review-file"} {
			command := sshWireCommand{Direction: direction, DestinationPath: t.TempDir(), Items: []sshSftpTransferItem{{SourcePath: source, Name: "source"}}}
			if _, err := buildSftpTransferPlans(client, command, context.Background()); err == nil {
				t.Fatalf("invalid/unavailable source accepted: %s %s", direction, source)
			}
		}
	}
	if _, err := buildSftpTransferPlans(client, sshWireCommand{Direction: "remote-to-local", Items: []sshSftpTransferItem{{Name: "source"}}}, context.Background()); err == nil {
		t.Fatal("empty remote source accepted")
	}
}

func TestSftpDirectoryPlanningStopsAtCapacityAndRootBounds(t *testing.T) {
	client := newSftpTestClient(t)
	source := t.TempDir()
	for _, remote := range []bool{false, true} {
		for _, full := range []bool{false, true} {
			plans := []sshSftpTransferPlan{}
			destination := strings.Repeat("d", sshSftpMaxPathBytes+1)
			if full {
				plans = make([]sshSftpTransferPlan, sshSftpMaxTransferPlanCount)
				destination = t.TempDir()
			}
			before := len(plans)
			item := sshSftpTransferItem{SourcePath: source, Name: "folder"}
			var err error
			if remote {
				item.SourcePath = sftpTestPath(source)
				err = appendRemoteTransferPlans(client, destination, item, &plans, context.Background())
			} else {
				err = appendLocalTransferPlans("local-to-remote", destination, item, &plans, context.Background())
			}
			if err == nil || len(plans) != before {
				t.Fatalf("invalid root/capacity mutated plans: remote=%v full=%v len=%d err=%v", remote, full, len(plans), err)
			}
		}
	}
	for _, plan := range []sshSftpTransferPlan{
		{sourcePath: strings.Repeat("s", sshSftpMaxPathBytes+1)},
		{displayName: strings.Repeat("é", sshSftpMaxNameBytes+1)},
	} {
		plans := []sshSftpTransferPlan{}
		if err := appendSftpTransferPlan(&plans, plan); err == nil || len(plans) != 0 {
			t.Fatal("invalid metadata was stored in plans")
		}
	}
}

func TestSftpRemoteWalkSkipsUnsafeEntriesAndHonorsCancellation(t *testing.T) {
	directory, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	client := newSftpReviewRequestClient(t, sftp.Handlers{FileList: sftpReviewFileList(func(request *sftp.Request) (sftp.ListerAt, error) {
		if request.Method != "List" {
			return sftpReviewLister{directory}, nil
		}
		return sftpReviewLister{
			sftpReviewNamedInfo{FileInfo: info, name: "\x00unsafe"},
			sftpReviewNamedInfo{FileInfo: info, name: "bad\\name"},
			sftpReviewNamedInfo{FileInfo: info, name: "safe.txt"},
		}, nil
	})})
	plans, err := buildSftpTransferPlans(client, sshWireCommand{Direction: "remote-to-local", DestinationPath: t.TempDir(), Items: []sshSftpTransferItem{{SourcePath: "/root", Name: "folder"}}}, context.Background())
	if err != nil || len(plans) != 2 || plans[1].displayName != "folder/safe.txt" {
		t.Fatalf("unsafe entry filtering = %#v, %v", plans, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := walkRemoteTransferPlans(client, "/root", t.TempDir(), "folder", &plans, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled walk = %v", err)
	}
}
