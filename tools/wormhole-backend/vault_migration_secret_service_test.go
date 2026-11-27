package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// Model the wire response shapes produced by godbus (including struct fields as
// []any), not a mock of the migration store. No desktop keychain is accessed.
type migrationSecretServiceFixture struct {
	t                                        *testing.T
	path                                     dbus.ObjectPath
	locked                                   []dbus.ObjectPath
	extra                                    []dbus.ObjectPath
	value                                    []byte
	responses                                [][]byte
	attribute                                string
	deleted, closed, sessions, sessionClosed int
	intercept                                func(string) ([]any, error, bool)
}

const migrationTestSession dbus.ObjectPath = "/org/freedesktop/secrets/session/test"
const migrationTestItem dbus.ObjectPath = "/org/freedesktop/secrets/collection/test/item/test"

func (f *migrationSecretServiceFixture) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	f.t.Helper()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.intercept != nil {
		if body, err, handled := f.intercept(method); handled {
			return body, err
		}
	}
	switch {
	case strings.HasSuffix(method, ".SearchItems"):
		attributes, ok := args[0].(map[string]string)
		if !ok || len(attributes) != 2 || attributes["service"] != "Wormhole" || attributes[f.attribute] != "credential:11111111-1111-4111-8111-111111111111" {
			f.t.Fatal("wrong lookup attributes", attributes)
		}
		unlocked := append([]dbus.ObjectPath{}, f.extra...)
		if f.path != "" {
			unlocked = append(unlocked, f.path)
		}
		return []any{unlocked, f.locked}, nil
	case strings.HasSuffix(method, ".OpenSession"):
		if args[0] != "plain" || args[1].(dbus.Variant).Value() != "" {
			f.t.Fatal("wrong session algorithm")
		}
		f.sessions++
		return []any{dbus.MakeVariant(""), migrationTestSession}, nil
	case strings.HasSuffix(method, ".GetSecret"):
		if path != f.path || args[0] != migrationTestSession {
			f.t.Fatal("wrong secret path/session")
		}
		value := bytes.Clone(f.value)
		f.responses = append(f.responses, value)
		return []any{[]any{migrationTestSession, []byte{}, value, "application/octet-stream"}}, nil
	case strings.HasSuffix(method, ".Delete"):
		if path != f.path {
			f.t.Fatal("wrong delete path")
		}
		f.deleted++
		f.path = ""
		return []any{dbus.ObjectPath("/")}, nil
	case method == "org.freedesktop.Secret.Session.Close":
		if path != migrationTestSession {
			f.t.Fatal("wrong closed session")
		}
		f.sessionClosed++
		return nil, nil
	default:
		f.t.Fatal("unexpected method", method)
		return nil, errors.New("unexpected method")
	}
}

func (f *migrationSecretServiceFixture) store(encoding string, maximum int) migrationCredentialStore {
	f.t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	f.attribute = "username"
	if encoding == linuxLegacySecretServiceEncoding {
		f.attribute = "account"
	}
	store, err := migrationSecretServiceStore(legacyInventoryRow{ID: id, Reference: id, Encoding: encoding}, maximum, f.call, func() { f.closed++ })
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(store.Close)
	return store
}

func TestVaultMigrationSecretServiceExactValuesAndAbsence(t *testing.T) {
	for _, encoding := range []string{linuxLegacySecretServiceEncoding, linuxSecretServiceEncoding} {
		for _, value := range [][]byte{nil, {}, []byte(" \x00\nsecret\n ")} {
			f := &migrationSecretServiceFixture{t: t, path: migrationTestItem, value: value}
			store := f.store(encoding, 1024)
			ctx := context.Background()
			got, present, err := store.Load(ctx)
			if err != nil || !present || !bytes.Equal(got, value) {
				t.Fatal("changed exact secret", err)
			}
			for _, response := range f.responses {
				if !bytes.Equal(response, make([]byte, len(response))) {
					t.Fatal("wire secret retained")
				}
			}
			if err := store.Delete(ctx); err != nil {
				t.Fatal(err)
			}
			if err := store.Delete(ctx); err != nil {
				t.Fatal("uncertain deletion not idempotent", err)
			}
			if got, present, err := store.Load(ctx); err != nil || present || len(got) != 0 {
				t.Fatal("missing item misreported", err)
			}
			store.Close()
			store.Close()
			if f.deleted != 1 || f.sessions != 1 || f.closed != 1 || f.sessionClosed != 1 {
				t.Fatal("bad lifecycle", f)
			}
			if _, _, err := store.Load(ctx); err == nil {
				t.Fatal("read closed store")
			}
			if err := store.Delete(ctx); err == nil {
				t.Fatal("delete closed store")
			}
		}
	}
}

func TestVaultMigrationSecretServiceRejectsAmbiguousLookup(t *testing.T) {
	for _, kind := range []string{"locked", "duplicate", "root", "invalid", "unavailable", "malformed", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := &migrationSecretServiceFixture{t: t, path: migrationTestItem, value: []byte("secret")}
			store := f.store(linuxSecretServiceEncoding, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "locked":
				f.path = ""
				f.locked = []dbus.ObjectPath{migrationTestItem}
			case "duplicate":
				f.extra = []dbus.ObjectPath{migrationTestItem}
			case "root":
				f.path = "/"
			case "invalid":
				f.path = "invalid path"
			case "unavailable":
				f.intercept = func(string) ([]any, error, bool) { return nil, errors.New("unavailable"), true }
			case "malformed":
				f.intercept = func(string) ([]any, error, bool) { return []any{"invalid"}, nil, true }
			case "cancel":
				cancel()
			}
			if _, present, err := store.Load(ctx); err == nil || present {
				t.Fatal("ambiguous lookup accepted")
			}
			if err := store.Delete(ctx); err == nil || f.deleted != 0 {
				t.Fatal("deleted without verified selection")
			}
			store.Close()
			if f.closed != 1 || f.sessions != 0 {
				t.Fatal("failed lookup leaked or opened session")
			}
		})
	}
}

func TestVaultMigrationSecretServiceRejectsSessionAndSecretFailures(t *testing.T) {
	for _, kind := range []string{"session-error", "session-malformed", "session-root", "session-invalid", "secret-error", "secret-malformed", "wrong-session", "parameters", "oversize", "cancel-secret"} {
		t.Run(kind, func(t *testing.T) {
			f := &migrationSecretServiceFixture{t: t, path: migrationTestItem}
			store := f.store(linuxSecretServiceEncoding, 4)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value, parameters := []byte("ok"), []byte{}
			f.intercept = func(method string) ([]any, error, bool) {
				if strings.HasSuffix(method, ".OpenSession") {
					switch kind {
					case "session-error":
						return nil, errors.New("unavailable"), true
					case "session-malformed":
						return []any{"invalid"}, nil, true
					case "session-root":
						return []any{dbus.MakeVariant(""), dbus.ObjectPath("/")}, nil, true
					case "session-invalid":
						return []any{dbus.MakeVariant(""), dbus.ObjectPath("invalid path")}, nil, true
					}
				}
				if strings.HasSuffix(method, ".GetSecret") {
					session := migrationTestSession
					var err error
					switch kind {
					case "secret-error":
						err = errors.New("unavailable")
					case "secret-malformed":
						return []any{[]any{value}}, nil, true
					case "wrong-session":
						session = "/other"
					case "parameters":
						parameters = []byte("unexpected")
					case "oversize":
						value = []byte("oversize")
					case "cancel-secret":
						cancel()
					}
					return []any{[]any{session, parameters, value, "text/plain"}}, err, true
				}
				return nil, nil, false
			}
			if _, present, err := store.Load(ctx); err == nil || present {
				t.Fatal("bad secret accepted")
			}
			if err := store.Delete(context.Background()); err == nil || f.deleted != 0 {
				t.Fatal("failed secret load authorized deletion")
			}
			if !strings.HasPrefix(kind, "session-") && (!bytes.Equal(value, make([]byte, len(value))) || !bytes.Equal(parameters, make([]byte, len(parameters)))) {
				t.Fatal("rejected wire secret retained")
			}
		})
	}
}

func TestVaultMigrationSecretServiceDeletionFailures(t *testing.T) {
	for _, kind := range []string{"changed-item", "locked", "prompt", "malformed", "unavailable", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := &migrationSecretServiceFixture{t: t, path: migrationTestItem, value: []byte("secret")}
			store := f.store(linuxSecretServiceEncoding, 1024)
			ctx := context.Background()
			if _, _, err := store.Load(ctx); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "changed-item":
				f.path = "/replacement"
			case "locked":
				f.locked = []dbus.ObjectPath{migrationTestItem}
			default:
				f.intercept = func(method string) ([]any, error, bool) {
					if !strings.HasSuffix(method, ".Delete") {
						return nil, nil, false
					}
					switch kind {
					case "prompt":
						return []any{dbus.ObjectPath("/prompt")}, nil, true
					case "malformed":
						return []any{42}, nil, true
					case "unavailable":
						return nil, errors.New("unavailable"), true
					case "cancel":
						return nil, context.Canceled, true
					}
					return nil, nil, false
				}
			}
			if err := store.Delete(ctx); err == nil {
				t.Fatal("failed deletion accepted")
			}
			if f.deleted != 0 {
				t.Fatal("replacement removed")
			}
		})
	}
}

func TestVaultMigrationSecretServiceValidationAndBodyWipe(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	valid := legacyInventoryRow{ID: id, Reference: id, Encoding: linuxSecretServiceEncoding}
	call := func(context.Context, dbus.ObjectPath, string, ...any) ([]any, error) {
		t.Fatal("invalid store used connection")
		return nil, nil
	}
	for _, kind := range []string{"id", "reference", "encoding", "zero", "oversize", "call", "close"} {
		row, maximum, fn, close := valid, 1024, migrationSecretServiceCall(call), func() {}
		switch kind {
		case "id":
			row.ID = "bad"
		case "reference":
			row.Reference = "bad"
		case "encoding":
			row.Encoding = darwinKeychainEncoding
		case "zero":
			maximum = 0
		case "oversize":
			maximum = backendMaxTunnelRequestBytes + 1
		case "call":
			fn = nil
		case "close":
			close = nil
		}
		if _, err := migrationSecretServiceStore(row, maximum, fn, close); err == nil {
			t.Fatal("invalid store accepted", kind)
		}
	}
	value, params := []byte("value"), []byte("params")
	wipeMigrationDBusBody([]any{migrationDBusSecret{Value: value, Parameters: params}})
	if !bytes.Equal(value, make([]byte, len(value))) || !bytes.Equal(params, make([]byte, len(params))) {
		t.Fatal("typed secret retained")
	}
}

func TestVaultMigrationSecretServiceRetriesSessionFailure(t *testing.T) {
	f := &migrationSecretServiceFixture{t: t, path: migrationTestItem, value: []byte("original")}
	store := f.store(linuxSecretServiceEncoding, 1024)
	f.intercept = func(method string) ([]any, error, bool) {
		if strings.HasSuffix(method, ".OpenSession") {
			return []any{dbus.MakeVariant(""), dbus.ObjectPath("/")}, nil, true
		}
		return nil, nil, false
	}
	if _, _, err := store.Load(context.Background()); err == nil {
		t.Fatal("root session accepted")
	}
	f.intercept = nil
	value, present, err := store.Load(context.Background())
	if err != nil || !present || !bytes.Equal(value, f.value) || f.sessions != 1 {
		t.Fatal("failed session poisoned retry", err)
	}
}
