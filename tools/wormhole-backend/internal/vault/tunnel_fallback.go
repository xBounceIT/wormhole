package vault

// TunnelFallbackBinding ties one separately authorized SSL attempt to the exact
// original IPsec source and connection. The second RequestID is a fresh attempt;
// both Host/Port values identify the connection destination, not the VPN gateway.
// This public context grants no authority. Its native owner must verify the
// encrypted primary->fallback reference, fresh source permissions and original
// process retirement before sealing, and consume its recipient only once.
type TunnelFallbackBinding struct {
	Primary  TunnelBundleBinding `json:"primary"`
	Fallback TunnelBundleBinding `json:"fallback"`
}

// Validate checks public context shape only; it grants no source authority.
func (b TunnelFallbackBinding) Validate() error {
	_, err := b.info()
	return err
}

func (b TunnelFallbackBinding) info() ([]byte, error) {
	primary, err := b.Primary.info()
	if err != nil {
		return nil, err
	}
	fallback, err := b.Fallback.info()
	if err != nil {
		return nil, err
	}
	p, f := b.Primary, b.Fallback
	if p.Kind != 9 || f.Kind != 2 || p.TunnelConfigID == f.TunnelConfigID || p.RequestID == f.RequestID ||
		p.WorkspaceID != f.WorkspaceID || p.FileID != f.FileID || p.NodeID != f.NodeID || p.SessionID != f.SessionID ||
		p.Protocol != f.Protocol || p.Host != f.Host || p.Port != f.Port || p.Epoch != f.Epoch {
		return nil, ErrPolicy
	}
	return canonical("wormhole/v1/tunnel-fallback", primary, fallback), nil
}

// The configuration is borrowed only for sealing and remains native-only. This
// purpose cannot be opened as an ordinary tunnel or routed credential handoff.
func SealTunnelFallback(public []byte, binding TunnelFallbackBinding, configuration []byte) (SealedBundle, error) {
	if len(configuration) == 0 || len(configuration) > MaxSecretBytes {
		return SealedBundle{}, ErrFormat
	}
	info, err := binding.info()
	if err != nil {
		return SealedBundle{}, err
	}
	return sealBundlePayload(public, info, configuration)
}

func OpenTunnelFallback(private []byte, binding TunnelFallbackBinding, bundle SealedBundle) ([]byte, error) {
	if err := validateSealedBundle(bundle); err != nil {
		return nil, err
	}
	info, err := binding.info()
	if err != nil {
		return nil, err
	}
	value, err := openBundlePayload(private, info, bundle)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		Wipe(value)
		return nil, ErrFormat
	}
	return value, nil
}
