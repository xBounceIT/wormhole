package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

type migrationSecretServiceCall func(context.Context, dbus.ObjectPath, string, ...any) ([]any, error)
type migrationDBusSecret struct {
	Session           dbus.ObjectPath
	Parameters, Value []byte
	ContentType       string
}

// Secret Service searches distinguish unlocked, locked and absent items. Never
// infer absence from secret-tool's ambiguous exit status or delete a collection.
// https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html
func migrationSecretServiceStore(row legacyInventoryRow, maximum int, call migrationSecretServiceCall, closeConnection func()) (migrationCredentialStore, error) {
	account, err := credentialSecretAccount(strings.ToLower(row.ID), row.Reference)
	attribute := ""
	switch strings.TrimSpace(row.Encoding) {
	case linuxLegacySecretServiceEncoding:
		attribute = "account"
	case linuxSecretServiceEncoding:
		attribute = "username"
	}
	if err != nil || attribute == "" || maximum < 1 || maximum > backendMaxTunnelRequestBytes || call == nil || closeConnection == nil {
		return migrationCredentialStore{}, errVaultMigrationSource
	}
	const service = "org.freedesktop.Secret.Service."
	const item = "org.freedesktop.Secret.Item."
	const root dbus.ObjectPath = "/org/freedesktop/secrets"
	var session, selected dbus.ObjectPath
	closed := false
	lookup := func(ctx context.Context) (dbus.ObjectPath, error) {
		if closed || ctx.Err() != nil {
			return "", errVaultMigrationSource
		}
		body, err := call(ctx, root, service+"SearchItems", map[string]string{"service": "Wormhole", attribute: account})
		var unlocked, locked []dbus.ObjectPath
		if err != nil || dbus.Store(body, &unlocked, &locked) != nil || len(locked) != 0 || len(unlocked) > 1 {
			return "", errVaultMigrationSource
		}
		if len(unlocked) == 0 {
			return "", nil
		}
		if !unlocked[0].IsValid() || unlocked[0] == "/" {
			return "", errVaultMigrationSource
		}
		return unlocked[0], nil
	}
	store := migrationCredentialStore{}
	store.Load = func(ctx context.Context) ([]byte, bool, error) {
		selected = ""
		path, err := lookup(ctx)
		if err != nil {
			return nil, false, err
		}
		if path == "" {
			return nil, false, nil
		}
		if session == "" {
			body, err := call(ctx, root, service+"OpenSession", "plain", dbus.MakeVariant(""))
			var output dbus.Variant
			var opened dbus.ObjectPath
			if err != nil || dbus.Store(body, &output, &opened) != nil || !opened.IsValid() || opened == "/" {
				return nil, false, errVaultMigrationSource
			}
			session = opened
		}
		body, err := call(ctx, path, item+"GetSecret", session)
		defer wipeMigrationDBusBody(body)
		var secret migrationDBusSecret
		decodeErr := dbus.Store(body, &secret)
		defer clearBytes(secret.Value)
		defer clearBytes(secret.Parameters)
		if err != nil || decodeErr != nil || secret.Session != session || len(secret.Parameters) != 0 || len(secret.Value) > maximum || ctx.Err() != nil {
			return nil, false, errVaultMigrationSource
		}
		selected = path
		return bytes.Clone(secret.Value), true, nil
	}
	store.Delete = func(ctx context.Context) error {
		if selected == "" {
			return errVaultMigrationSource
		}
		path, err := lookup(ctx)
		if err != nil {
			return err
		}
		if path == "" {
			return nil
		}
		if path != selected {
			return errVaultMigrationSource
		}
		body, err := call(ctx, path, item+"Delete")
		var prompt dbus.ObjectPath
		if err != nil || dbus.Store(body, &prompt) != nil || prompt != "/" || ctx.Err() != nil {
			return errVaultMigrationSource
		}
		return nil
	}
	store.Close = sync.OnceFunc(func() {
		closed = true
		if session != "" && session.IsValid() && session != "/" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = call(ctx, session, "org.freedesktop.Secret.Session.Close")
		}
		closeConnection()
	})
	return store, nil
}

func wipeMigrationDBusBody(body []any) {
	for _, value := range body {
		switch value := value.(type) {
		case []byte:
			clearBytes(value)
		case []any:
			wipeMigrationDBusBody(value)
		case migrationDBusSecret:
			clearBytes(value.Value)
			clearBytes(value.Parameters)
		}
	}
}
