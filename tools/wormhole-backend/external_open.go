package main

// externalOpenCommand returns the native desktop launcher and arguments for a URL or an
// absolute local path. Callers must still validate the target for their own trust boundary.
func externalOpenCommand(goos, target string) (string, []string) {
	switch goos {
	case "windows":
		return "rundll32.exe", []string{"url.dll,FileProtocolHandler", target}
	case "darwin":
		return "open", []string{target}
	default:
		return "xdg-open", []string{target}
	}
}
