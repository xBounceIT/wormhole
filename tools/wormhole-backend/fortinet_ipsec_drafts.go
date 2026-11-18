package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

const fortinetIPsecDraftLifetime = 15 * time.Minute
const maxFortinetIPsecDraftEntries = 64

type fortinetIPsecDraftEntry struct {
	field   string
	key     [authProtectionKeyLength]byte
	sealed  []byte
	expires time.Time
	timer   *time.Timer
}

// Drafts live only in the Go service. A successful save, discard, lock, or
// expiration destroys the corresponding encryption keys and ciphertext.
type fortinetIPsecDraftStore struct {
	mu      sync.Mutex
	saveMu  sync.Mutex
	entries map[string]*fortinetIPsecDraftEntry
}

func isFortinetIPsecDraftField(field string) bool {
	return field == "PreSharedKey" || field == "Password"
}

func validFortinetIPsecDraftSecret(secret []byte) bool {
	if len(secret) > 4096 || len(bytes.TrimSpace(secret)) == 0 || !utf8.Valid(secret) {
		return false
	}
	for _, ch := range secret {
		if ch < 32 || ch == 127 {
			return false
		}
	}
	return true
}

func (s *fortinetIPsecDraftStore) stage(id, field string, secret []byte) error {
	if normalizeTunnelID(id) != id || id == "" || !isFortinetIPsecDraftField(field) || !validFortinetIPsecDraftSecret(secret) {
		return errors.New("Fortinet IPsec draft credential is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= maxFortinetIPsecDraftEntries || s.entries[id] != nil {
		return errors.New("could not stage the Fortinet IPsec credential")
	}
	entry := &fortinetIPsecDraftEntry{field: field, expires: time.Now().Add(fortinetIPsecDraftLifetime)}
	if _, err := rand.Read(entry.key[:]); err != nil {
		return errors.New("could not protect the Fortinet IPsec credential")
	}
	sealed, err := encryptAuthDocument(secret, entry.key[:])
	if err != nil {
		clearBytes(entry.key[:])
		return errors.New("could not protect the Fortinet IPsec credential")
	}
	entry.sealed = sealed
	if s.entries == nil {
		s.entries = make(map[string]*fortinetIPsecDraftEntry)
	}
	s.entries[id] = entry
	entry.timer = time.AfterFunc(fortinetIPsecDraftLifetime, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.entries[id] == entry {
			s.discardLocked(id)
		}
	})
	return nil
}

func (s *fortinetIPsecDraftStore) open(id, field string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[id]
	if entry == nil || entry.field != field {
		return nil, errFortinetIPsecDraftExpired
	}
	if !time.Now().Before(entry.expires) {
		s.discardLocked(id)
		return nil, errFortinetIPsecDraftExpired
	}
	value, err := decryptAuthDocument(entry.sealed, entry.key[:])
	if err != nil {
		return nil, errors.New("could not open the protected Fortinet IPsec credential")
	}
	return value, nil
}

var errFortinetIPsecDraftExpired = errors.New("the Fortinet IPsec credential draft expired; enter the credentials again")

func (s *fortinetIPsecDraftStore) discardLocked(id string) {
	if entry := s.entries[id]; entry != nil {
		entry.timer.Stop()
		clearBytes(entry.key[:])
		clearBytes(entry.sealed)
		delete(s.entries, id)
	}
}

func (s *fortinetIPsecDraftStore) discard(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discardLocked(id)
}

func (s *fortinetIPsecDraftStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.entries {
		s.discardLocked(id)
	}
}

func (s *fortinetIPsecDraftStore) save(databasePath string, request tunnelWriteRequest, references map[string]string, create bool) (tunnelDetails, error) {
	// Serialize reference consumption without blocking lock or discard during a database write.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	var settings map[string]json.RawMessage
	if json.Unmarshal(request.Settings, &settings) != nil || settings == nil {
		return tunnelDetails{}, errors.New("Fortinet IPsec settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	for field, reference := range references {
		if (field == "PreSharedKey" && tunnelSettingNumber(settings, "AuthMethod") == 1) ||
			(field == "Password" && fortinetUserAuth(settings) != 2) {
			continue
		}
		value, err := s.open(reference, field)
		if err != nil {
			return tunnelDetails{}, err
		}
		encoded, _ := json.Marshal(string(value))
		clearBytes(value)
		clearBytes(settings[field])
		settings[field] = encoded
		delete(settings, "Has"+field)
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return tunnelDetails{}, errors.New("Fortinet IPsec settings are invalid")
	}
	defer clearBytes(raw)
	request.Settings = raw
	var result tunnelDetails
	if create {
		result, err = createTunnel(databasePath, request)
	} else {
		result, err = updateTunnel(databasePath, request)
	}
	if err == nil {
		for _, reference := range references {
			s.discard(reference)
		}
	}
	return result, err
}
