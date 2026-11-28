package sharedpg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const changeChannel = "wormhole_changes"

var (
	ErrNotifications     = errors.New("shared PostgreSQL notification stream failed")
	ErrNotSubscribed     = errors.New("shared PostgreSQL change subscription is not active")
	ErrNotificationNoise = errors.New("shared PostgreSQL notification stream contains too many invalid hints")
)

// SubscribeChanges subscribes only the dedicated notification connection. It is
// idempotent. The caller must fetch get_changes_since AFTER this succeeds, before
// waiting for hints, to cover changes during startup and subscription setup.
func (s *Session) SubscribeChanges(ctx context.Context) (err error) {
	if ctx == nil {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	owned, opCtx, release, err := s.lease(ctx, 1)
	if err != nil {
		return err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return ErrNotifications
	}
	defer s.invalidateIfClosed(conn)
	if s.slots[1].subscribed {
		return nil
	}
	r := conn.ExecParams(opCtx, "listen "+changeChannel, nil, nil, nil, nil)
	if r.NextRow() || len(r.FieldDescriptions()) != 0 {
		s.discardConnection(conn)
		return ErrNotifications
	}
	tag, queryErr := r.Close()
	if queryErr != nil {
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return ErrNotifications
	}
	if opCtx.Err() != nil {
		return opCtx.Err()
	}
	if tag.String() != "LISTEN" {
		s.discardConnection(conn)
		return ErrNotifications
	}
	s.slots[1].subscribed = true
	return nil
}

// NextChangeHint returns only a canonical, nonzero UUID. Hints are untrusted and
// confer no authority: fetch authenticated changes rather than updating local
// state from this ID. No notification payload or server diagnostics escape.
func (s *Session) NextChangeHint(ctx context.Context) (string, error) {
	owned, opCtx, release, err := s.lease(ctx, 1)
	if err != nil {
		return "", err
	}
	defer release()
	conn, ok := owned.(*pgconn.PgConn)
	if !ok {
		return "", ErrNotifications
	}
	defer s.invalidateIfClosed(conn)
	if !s.slots[1].subscribed {
		return "", ErrNotSubscribed
	}
	for ignored := 0; ignored < 64; ignored++ {
		msg, err := conn.ReceiveMessage(opCtx)
		if err != nil {
			if opCtx.Err() != nil {
				return "", opCtx.Err()
			}
			s.discardConnection(conn)
			return "", ErrNotifications
		}
		switch value := msg.(type) {
		case *pgproto3.NotificationResponse:
			if value.Channel != changeChannel || !validChangeHint(value.Payload) {
				continue
			}
			if opCtx.Err() != nil {
				return "", opCtx.Err()
			}
			return value.Payload, nil
		case *pgproto3.NoticeResponse, *pgproto3.ParameterStatus:
			continue
		default:
			s.discardConnection(conn)
			return "", ErrNotifications
		}
	}
	return "", ErrNotificationNoise
}

func validChangeHint(value string) bool {
	if len(value) != 36 {
		return false
	}
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func (s *Session) invalidateIfClosed(conn *pgconn.PgConn) {
	if conn.IsClosed() {
		s.ready.Store(false)
		s.cancel()
	}
}

// The owner retains the connection until its ordinary Close confirms cleanup.
func (s *Session) discardConnection(conn *pgconn.PgConn) {
	s.ready.Store(false)
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
