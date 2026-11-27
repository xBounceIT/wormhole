package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

var errManifestUsage = errors.New(`Manifest commands
  sign-update-manifest <release tag> <artifact directory> <public key hex>
  sign-update-manifest sign-system-manifest <release tag> <artifact directory> <public key hex>
  sign-update-manifest inventory-installation <release tag> <target> <package directory>
  sign-update-manifest sign-installation <release tag> <target> <inventory file> <public key hex>
  sign-update-manifest verify-installation <target> <package directory> <public key hex>`)

func runManifestCommand(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errManifestUsage
	}
	switch args[0] {
	case "sign-system-manifest":
		if len(args) != 4 {
			return errManifestUsage
		}
		m, err := updateauth.NewSystemManifest(args[1])
		if err != nil {
			return err
		}
		return signManifestFiles(m, updateauth.SystemManifestName, args[2], args[3], input)
	case "inventory-installation":
		if len(args) != 4 {
			return errManifestUsage
		}
		m, err := updateauth.InventoryInstallation(ctx, args[3], args[1], args[2])
		if err != nil {
			return err
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return err
		}
		_, err = output.Write(raw)
		return err
	case "sign-installation":
		if len(args) != 5 {
			return errManifestUsage
		}
		return signInstallationInventory(args[1], args[2], args[3], args[4], input, output)
	case "verify-installation":
		if len(args) != 4 {
			return errManifestUsage
		}
		root, err := filepath.Abs(args[2])
		if err != nil {
			return err
		}
		key, err := updateauth.ParsePublicKey(args[3])
		if err != nil {
			return err
		}
		_, err = updateauth.VerifyInstalledTree(ctx, root, args[1], key)
		return err
	default:
		if len(args) != 3 {
			return errManifestUsage
		}
		return signRelease(args[0], args[1], args[2], input)
	}
}

func signInstallationInventory(tag, target, path, expectedPublicKey string, input io.Reader, output io.Writer) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := updateauth.OpenArtifact(root, filepath.Base(path))
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, updateauth.MaxInstallationProof+1))
	if err != nil {
		return updateauth.ErrManifest
	}
	m, err := updateauth.ParseInstallationInventory(raw)
	if err != nil || m.ReleaseTag != tag || m.Target != target {
		return updateauth.ErrManifest
	}
	key, err := readSigningKey(expectedPublicKey, input)
	if err != nil {
		return err
	}
	defer clear(key)
	proof, err := updateauth.SignInstallation(m, key)
	if err != nil {
		return err
	}
	_, err = output.Write(proof)
	return err
}
