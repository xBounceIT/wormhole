package main

func publishVaultFile(source, target string) error {
	// Deliberately omit MOVEFILE_REPLACE_EXISTING.
	return moveWindowsFileWithWriteThrough(source, target, 0)
}
