// Browser-only target for HPKE's optional Node crypto import. Never add a Node
// fallback or an external import to the owning extension's packaged asset.
export const webcrypto = globalThis.crypto;
