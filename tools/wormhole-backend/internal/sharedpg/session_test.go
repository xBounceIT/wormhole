package sharedpg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type testOwnedConnection struct {
	mu                      sync.Mutex
	closed, delayed, refuse bool
	closes                  int
	done                    chan struct{}
	once                    sync.Once
}

func newTestConnection() *testOwnedConnection { return &testOwnedConnection{done: make(chan struct{})} }
func (c *testOwnedConnection) Close(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	if c.refuse {
		return errors.New("private close error")
	}
	c.closed = true
	if !c.delayed {
		c.finish()
	}
	return nil
}
func (c *testOwnedConnection) IsClosed() bool             { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
func (c *testOwnedConnection) CleanupDone() chan struct{} { return c.done }
func (c *testOwnedConnection) finish()                    { c.once.Do(func() { close(c.done) }) }

func readySession(t *testing.T, notifications bool) (*Session, []*testOwnedConnection) {
	t.Helper()
	s := NewSession()
	var conns []*testOwnedConnection
	err := s.open(context.Background(), notifications, func(context.Context) (ownedConnection, error) {
		c := newTestConnection()
		conns = append(conns, c)
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return s, conns
}

func TestSessionDoneSignalsExplicitClose(t *testing.T) {
	s := NewSession()
	select {
	case <-s.Done():
		t.Fatal("new owner already invalidated")
	default:
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("close did not notify the owning controller")
	}
}

func TestSessionOwnsAtMostTwoConnections(t *testing.T) {
	for _, listen := range []bool{false, true} {
		s, conns := readySession(t, listen)
		want := 1
		if listen {
			want = 2
		}
		if len(conns) != want {
			t.Fatal("incorrect count")
		}
		if err := s.open(context.Background(), listen, func(context.Context) (ownedConnection, error) { t.Fatal("unexpected reconnect"); return nil, nil }); err != ErrSessionStarted {
			t.Fatal(err)
		}
		for i := 0; i < want; i++ {
			c, ctx, release, err := s.lease(context.Background(), i)
			if err != nil || c != conns[i] || ctx.Err() != nil {
				t.Fatal("bad lease")
			}
			release()
			release()
		}
		if !listen {
			if _, _, _, err := s.lease(context.Background(), 1); err != ErrSessionClosed {
				t.Fatal(err)
			}
		}
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, c := range conns {
			if c.closes != 1 {
				t.Fatal("non-idempotent close")
			}
		}
		if err := s.open(context.Background(), listen, nil); err != ErrSessionClosed {
			t.Fatal(err)
		}
	}
}

func TestSessionCloseCancelsActiveAndQueuedLeases(t *testing.T) {
	s, _ := readySession(t, true)
	_, active, release, err := s.lease(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, listener, releaseListener, err := s.lease(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	go func() {
		_, _, r, e := s.lease(context.Background(), 0)
		if r != nil {
			r()
		}
		queued <- e
	}()
	closed := make(chan error, 1)
	go func() { closed <- s.Close(context.Background()) }()
	select {
	case <-active.Done():
	case <-time.After(time.Second):
		t.Fatal("active lease not canceled")
	}
	select {
	case <-listener.Done():
	case <-time.After(time.Second):
		t.Fatal("listener not canceled")
	}
	select {
	case <-closed:
		t.Fatal("close returned while operations owned connections")
	default:
	}
	release()
	releaseListener()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := <-queued; err != context.Canceled && err != ErrSessionClosed {
		t.Fatalf("queued lease survived: %v", err)
	}
	if _, _, _, err := s.lease(context.Background(), 0); err != ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestSessionRetainsUnconfirmedCleanup(t *testing.T) {
	s, conns := readySession(t, false)
	c := conns[0]
	c.delayed = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	if s.slots[0].conn != c {
		t.Fatal("discarded live cleanup")
	}
	c.finish()
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.slots[0].conn != nil {
		t.Fatal("cleanup not released")
	}
	s2, conns2 := readySession(t, true)
	conns2[0].refuse = true
	if err := s2.Close(context.Background()); err != ErrSessionCleanup {
		t.Fatal(err)
	}
	if s2.slots[0].conn != conns2[0] {
		t.Fatal("lost uncertain connection")
	}
	if !conns2[1].IsClosed() || s2.slots[1].conn != nil {
		t.Fatal("one failed close prevented cleanup of the other connection")
	}
	conns2[0].refuse = false
	if err := s2.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionPartialOpenCleanup(t *testing.T) {
	s := NewSession()
	first := newTestConnection()
	calls := 0
	err := s.open(context.Background(), true, func(context.Context) (ownedConnection, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, ErrConnectionLimit
	})
	if err != ErrConnectionLimit || !first.IsClosed() || s.ready.Load() {
		t.Fatal("partial open escaped")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = NewSession()
	first = newTestConnection()
	first.refuse = true
	calls = 0
	err = s.open(context.Background(), true, func(context.Context) (ownedConnection, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, ErrConnection
	})
	if err != ErrSessionCleanup || s.slots[0].conn != first {
		t.Fatal("partial cleanup lost")
	}
	first.refuse = false
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseDuringOpen(t *testing.T) {
	s := NewSession()
	entered := make(chan struct{})
	opened := make(chan error, 1)
	go func() {
		opened <- s.open(context.Background(), true, func(ctx context.Context) (ownedConnection, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	<-entered
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-opened; err != context.Canceled {
		t.Fatal(err)
	}
	if s.ready.Load() {
		t.Fatal("closed session became ready")
	}
}

func TestSessionInputAndCancellationBoundaries(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	if err := s.open(nil, false, nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := s.Close(nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	for _, index := range []int{-1, 2} {
		if _, _, _, err := s.lease(context.Background(), index); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, _, _, err := s.lease(nil, 0); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, _, _, err := s.lease(context.Background(), 0); err != ErrSessionClosed {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.open(ctx, false, nil); err != context.Canceled {
		t.Fatal(err)
	}
	s2, conns := readySession(t, false)
	if _, _, _, err := s2.lease(ctx, 0); err != context.Canceled {
		t.Fatal(err)
	}
	if err := s2.Close(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	if s2.slots[0].conn != conns[0] {
		t.Fatal("discarded canceled cleanup")
	}
	s3 := NewSession()
	bad := settings()
	bad.Database = ""
	if err := s3.Open(context.Background(), bad, []byte("secret"), ChangePolicy{TransactionPooler: true}); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := s3.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s4 := NewSession()
	if err := s4.open(context.Background(), false, func(context.Context) (ownedConnection, error) { return nil, nil }); err != ErrConnection {
		t.Fatal(err)
	}
	if err := s4.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionLateDialAndExpiredLeaseCleanup(t *testing.T) {
	s := NewSession()
	c := newTestConnection()
	ctx, cancel := context.WithCancel(context.Background())
	err := s.open(ctx, false, func(context.Context) (ownedConnection, error) { cancel(); return c, nil })
	if err != context.Canceled || !c.IsClosed() {
		t.Fatal("late dial escaped cleanup")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s2, conns := readySession(t, false)
	_, _, release, err := s2.lease(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	closeCtx, done := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer done()
	if err := s2.Close(closeCtx); err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	if s2.slots[0].conn != conns[0] {
		t.Fatal("lost leased connection")
	}
	release()
	if err := s2.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s3, cs := readySession(t, false)
	_ = cs[0].Close(context.Background())
	if _, _, _, err := s3.lease(context.Background(), 0); err != ErrSessionClosed {
		t.Fatal(err)
	}
}

func TestSessionOwnsTwoAuthenticatedConnections(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	secret := []byte("native-session-device-secret")
	done := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			go func() { done <- serveWritableSessionConnection(conn, secret) }()
		}
	}()
	settings := settings()
	settings.Endpoints = []Endpoint{{"127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)}}
	s := NewSession()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer s.Close(context.Background())
	if err := s.Open(ctx, settings, secret, ChangePolicy{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c, _, release, err := s.lease(ctx, i)
		if err != nil || c == nil {
			t.Fatal("missing authenticated connection")
		}
		release()
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("missing wire termination")
		}
	}
}

func serveWritableSessionConnection(conn net.Conn, secret []byte) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	b := pgproto3.NewBackend(conn, conn)
	if err := initializeWritableTestConnection(b, secret); err != nil {
		return err
	}
	msg, err := b.Receive()
	if err != nil {
		return err
	}
	if _, ok := msg.(*pgproto3.Terminate); !ok {
		return fmt.Errorf("expected termination, got %T", msg)
	}
	return nil
}

func initializeWritableTestConnection(b *pgproto3.Backend, secret []byte) error {
	startup, err := b.ReceiveStartupMessage()
	if err != nil {
		return err
	}
	msg, ok := startup.(*pgproto3.StartupMessage)
	if !ok || msg.Parameters["client_encoding"] != "UTF8" {
		return fmt.Errorf("client did not request UTF8")
	}
	if err := authenticateTestClient(b, secret); err != nil {
		return err
	}
	for {
		msg, err := b.Receive()
		if err != nil {
			return err
		}
		if _, ok := msg.(*pgproto3.Sync); ok {
			break
		}
	}
	b.Send(&pgproto3.ParseComplete{})
	b.Send(&pgproto3.BindComplete{})
	b.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("transaction_read_only"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
	b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("off")}})
	b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SHOW")})
	b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := b.Flush(); err != nil {
		return err
	}
	return nil
}
