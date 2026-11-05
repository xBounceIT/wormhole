package smb2

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// A negotiated in-memory peer records the actual SMB requests. Authentication
// and signing remain in the unchanged upstream implementation.
type wormholePeer struct {
	responses    chan []byte
	closed       chan struct{}
	once         sync.Once
	next         []byte
	mu           sync.Mutex
	requests     [][]byte
	ignoreClose  bool
	rejectRename bool
}

func (peer *wormholePeer) Write(packet []byte) (int, error) {
	request := smb2.PacketCodec(packet)
	peer.mu.Lock()
	peer.requests = append(peer.requests, append([]byte(nil), packet...))
	peer.mu.Unlock()
	var response smb2.Packet
	timestamp := &smb2.Filetime{}
	switch request.Command() {
	case smb2.SMB2_CREATE:
		response = &smb2.CreateResponse{FileAttributes: smb2.FILE_ATTRIBUTE_NORMAL, FileId: &smb2.FileId{}, CreationTime: timestamp, LastAccessTime: timestamp, LastWriteTime: timestamp, ChangeTime: timestamp}
	case smb2.SMB2_SET_INFO:
		response = &smb2.SetInfoResponse{}
		if peer.rejectRename {
			response = &smb2.ErrorResponse{}
		}
	case smb2.SMB2_CLOSE:
		if peer.ignoreClose {
			return len(packet), nil
		}
		response = &smb2.CloseResponse{CreationTime: timestamp, LastAccessTime: timestamp, LastWriteTime: timestamp, ChangeTime: timestamp}
	case smb2.SMB2_CANCEL:
		return len(packet), nil
	default:
		return 0, os.ErrInvalid
	}
	*response.Header() = smb2.PacketHeader{Flags: 1, CreditCharge: 1, CreditRequestResponse: 1, MessageId: request.MessageId(), TreeId: request.TreeId(), SessionId: request.SessionId()}
	if request.Command() == smb2.SMB2_SET_INFO && peer.rejectRename {
		response.Header().Command = smb2.SMB2_SET_INFO
		response.Header().Status = 0xc0000035 // STATUS_OBJECT_NAME_COLLISION
	}
	data := make([]byte, response.Size())
	response.Encode(data)
	select {
	case peer.responses <- data:
		return len(packet), nil
	case <-peer.closed:
		return 0, net.ErrClosed
	}
}
func (peer *wormholePeer) ReadSize() (int, error) {
	select {
	case peer.next = <-peer.responses:
		return len(peer.next), nil
	case <-peer.closed:
		return 0, net.ErrClosed
	}
}
func (peer *wormholePeer) Read(data []byte) (int, error) {
	n := copy(data, peer.next)
	peer.next = peer.next[n:]
	return n, nil
}
func (peer *wormholePeer) Close() error { peer.once.Do(func() { close(peer.closed) }); return nil }
func (peer *wormholePeer) packets(command uint16) [][]byte {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	var packets [][]byte
	for _, packet := range peer.requests {
		if smb2.PacketCodec(packet).Command() == command {
			packets = append(packets, packet)
		}
	}
	return packets
}
func newWormholeShare(t *testing.T) (*Share, *wormholePeer) {
	t.Helper()
	peer := &wormholePeer{responses: make(chan []byte, 32), closed: make(chan struct{})}
	connection := newTestConn(peer)
	share := &Share{treeConn: &treeConn{session: &session{conn: connection}}, ctx: context.Background()}
	t.Cleanup(func() {
		_ = peer.Close()
		select {
		case <-connection.wdone:
		case <-time.After(time.Second):
			t.Error("SMB peer did not stop")
		}
	})
	return share, peer
}

func TestWormholeAtomicRenameUsesNativeCollisionFlag(t *testing.T) {
	for _, replace := range []bool{false, true} {
		share, peer := newWormholeShare(t)
		var err error
		if replace {
			err = share.Rename("source", "target")
		} else {
			err = share.RenameNoReplace("source", "target")
		}
		require.NoError(t, err)
		packets := peer.packets(smb2.SMB2_SET_INFO)
		require.Len(t, packets, 1)
		offset := binary.LittleEndian.Uint16(packets[0][72:74])
		want := byte(0)
		if replace {
			want = 1
		}
		require.Equal(t, want, packets[0][offset], "ReplaceIfExists must be enforced by the server")
		require.Len(t, peer.packets(smb2.SMB2_CLOSE), 1)
	}
	share, _ := newWormholeShare(t)
	require.Error(t, share.RenameNoReplace(`\source`, "target"))
	require.Error(t, share.RenameNoReplace("source", `\target`))
}

func TestWormholeCleanupClosesUsingIndependentContext(t *testing.T) {
	share, peer := newWormholeShare(t)
	ctx, cancel := context.WithCancel(context.Background())
	file, err := share.WithContext(ctx).OpenFile("file", os.O_WRONLY, 0o600)
	require.NoError(t, err)
	cancel()
	require.ErrorIs(t, file.Close(), context.Canceled)
	require.Empty(t, peer.packets(smb2.SMB2_CLOSE))
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	require.NoError(t, file.CloseContext(cleanup))
	require.Len(t, peer.packets(smb2.SMB2_CLOSE), 1)
	require.ErrorIs(t, file.CloseContext(cleanup), os.ErrInvalid)
	var missing *File
	require.ErrorIs(t, missing.CloseContext(cleanup), os.ErrInvalid)
	require.ErrorIs(t, missing.close(), os.ErrInvalid)
}

func TestWormholeCleanupContextIsBounded(t *testing.T) {
	share, peer := newWormholeShare(t)
	file, err := share.OpenFile("file", os.O_WRONLY, 0o600)
	require.NoError(t, err)
	peer.ignoreClose = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, file.CloseContext(ctx), context.DeadlineExceeded)
	require.Len(t, peer.packets(smb2.SMB2_CLOSE), 1)
}

func TestWormholeServerCollisionPreservesErrorAndClosesHandle(t *testing.T) {
	share, peer := newWormholeShare(t)
	peer.rejectRename = true
	err := share.RenameNoReplace("source", "target")
	require.Error(t, err)
	require.True(t, os.IsExist(err), err)
	require.Len(t, peer.packets(smb2.SMB2_CLOSE), 1)
}
