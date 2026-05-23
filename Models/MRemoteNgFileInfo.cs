namespace Wormhole.Models;

public sealed record MRemoteNgFileInfo(
    string ConfVersion,
    string EncryptionEngine,
    string BlockCipherMode,
    string Protected,
    bool FullFileEncryption,
    int KdfIterations,
    bool HasPasswordPayloads);
