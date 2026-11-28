package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

func signRelease(tag, directory, expectedPublicKey string, input io.Reader) error {
	manifest, err := updateauth.NewManifest(tag)
	if err != nil {
		return err
	}
	return signManifestFiles(manifest, updateauth.ManifestName, directory, expectedPublicKey, input)
}

func signManifestFiles(manifest updateauth.Manifest, filename, directory, expectedPublicKey string, input io.Reader) error {
	key, err := readSigningKey(expectedPublicKey, input)
	if err != nil {
		return err
	}
	defer clear(key)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	for i := range manifest.Artifacts {
		asset := &manifest.Artifacts[i]
		asset.Size, asset.SHA256, err = updateauth.Digest(root, asset.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", asset.Name, err)
		}
	}
	raw, err := updateauth.Sign(manifest, key)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		_ = root.Remove(filename)
		return err
	}
	return nil
}

func readSigningKey(expectedPublicKey string, input io.Reader) (ed25519.PrivateKey, error) {
	public, err := updateauth.ParsePublicKey(expectedPublicKey)
	if err != nil {
		return nil, err
	}
	// The hex seed is supplied through stdin. It never enters arguments,
	// artifacts, command output, or errors.
	encoded, err := io.ReadAll(io.LimitReader(input, 2*ed25519.SeedSize+3))
	defer clear(encoded)
	if err != nil || len(encoded) > 2*ed25519.SeedSize+2 {
		return nil, updateauth.ErrSignature
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if len(bytes.TrimSpace(encoded)) != 2*len(seed) {
		return nil, updateauth.ErrSignature
	}
	if _, err := hex.Decode(seed, bytes.TrimSpace(encoded)); err != nil {
		return nil, updateauth.ErrSignature
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !key.Public().(ed25519.PublicKey).Equal(public) {
		clear(key)
		return nil, errors.New("update signing key does not match the build pin")
	}
	return key, nil
}

func main() {
	if err := runManifestCommand(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errManifestUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
