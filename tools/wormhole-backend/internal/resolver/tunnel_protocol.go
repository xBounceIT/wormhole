package resolver

// TunnelProtocol names a protocol at the native route boundary. Empty means
// unsupported; release intent paths such as Reveal are deliberately separate.
func TunnelProtocol(protocol int) string {
	switch protocol {
	case 0:
		return "ssh"
	case 1:
		return "rdp"
	case 3:
		return "http"
	case 4:
		return "https"
	case 6:
		return "vnc"
	case 7:
		return "sftp"
	default:
		return ""
	}
}
