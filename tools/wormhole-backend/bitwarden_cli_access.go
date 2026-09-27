package main

import "strings"

// Content commands must use the session owned by Go. Without one, surface the
// on-demand authentication request before spawning a CLI that could prompt on
// stdin or inherit an unrelated BW_SESSION from the parent environment.
func requireBitwardenCliContentSession(args []string, environment map[string]string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "list", "get", "sync":
		if strings.TrimSpace(environment[bitwardenCliSessionEnvVar]) == "" {
			return &bitwardenCliVaultError{Message: "Bitwarden vault is locked. Unlock the vault to continue.", IsAuth: true}
		}
	}
	return nil
}
