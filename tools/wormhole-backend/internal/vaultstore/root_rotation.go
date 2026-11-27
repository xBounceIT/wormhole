package vaultstore

import "context"

// RootRotationTransforms belong to the native key owner. Storage lends only
// ciphertext/metadata, never receives a plaintext field or root key, and never
// treats these callbacks as an IPC capability. Callbacks must not reenter a store.
// Aggregate callbacks authenticate the old value and return only its new seal;
// domain revisions, timestamps, manifests and tombstones remain unchanged.
type RootRotationTransforms struct {
	Secret     func(Secret) (Secret, error)
	Credential func(Credential) ([]byte, error)
	Tunnel     func(Tunnel) ([]byte, error)
	Node       func(Node) ([]byte, error)
	LocalState func(LocalState) ([]byte, error)
	Profile    func([]byte) ([]byte, error)
}

func (t RootRotationTransforms) valid() bool {
	return t.Secret != nil && t.Credential != nil && t.Tunnel != nil && t.Node != nil && t.LocalState != nil && t.Profile != nil
}

// RootRotationCounts includes tombstones. A completed stage is still unpublished:
// its native controller must verify it with the new key and journal the source
// retirement/slot publication before presenting protection as enabled.
type RootRotationCounts struct {
	Credentials, Tunnels, Nodes, LocalStates, Secrets int
}

const MaxRootRotationRecords = 1_000_000

type RootRotationStore interface {
	Store
	BeginRootRotation(context.Context, string) (*RootRotationTarget, error)
	BeginEncryptedRootRotation(context.Context, string, []byte) (*RootRotationTarget, error)
	SettleRootRotationSource(context.Context) error
}
