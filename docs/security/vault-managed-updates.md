# Managed Wormhole updates

Use managed updates to approve a specific Wormhole release for vaults running in Hardened or Paranoid mode. Hardened uses public release notifications when the machine has no managed approval. Paranoid checks the local source only. A missing or invalid package under a configured approval produces a verification error.

| Platform | Staging directory                                      | Machine approval                                                                                    |
| -------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| Windows  | System ProgramData directory, under `Wormhole\Updates` | `ManagedUpdateManifestSHA256` of type `REG_SZ` in the 64-bit `HKLM\SOFTWARE\Policies\Wormhole` view |
| macOS    | `/Library/Application Support/Wormhole/Updates`        | `/Library/Managed Preferences/com.xbounceit.wormhole.update.sha256`                                 |
| Linux    | `/var/lib/wormhole/updates`                            | `/etc/wormhole/managed-update.sha256`                                                               |

1. On Windows or macOS, stage `Wormhole-UpdateManifest-v1.json` and the platform's versioned installer. On Linux, stage `Wormhole-UpdateManifest-v2.json` and exactly one DEB or RPM for each architecture you serve. Use files from the same release under their published names. Give users read access and restrict writes to administrators or the deployment service.
2. Publish the manifest’s SHA-256 digest to the machine approval. Use 64 hexadecimal digits without a filename. On macOS and Linux, publish the approval file atomically. Root must own the file and its parents. The client rejects symbolic links and writable policy paths.
3. In the unlocked vault, select **Check managed updates**. The app verifies the manifest against the public key built into Wormhole and copies the named installer to its cache. It checks the installer’s size and digest during the copy and before opening it. Windows requires the pinned Authenticode publisher. macOS requires the pinned Developer ID Team and notarization. On Linux, Wormhole separately verifies and reveals the DEB or RPM in the administrator's staging directory. Root must own the package and its parent directories, with writes restricted to root. Withdrawing the staged package or staging both formats for the same architecture invalidates the selection.

Remove the approval or change its digest to withdraw an older release. Wormhole checks the current approval before downloading and again before opening a cached installer. Only versions newer than the running app are offered.

On Windows, the Go worker holds the installer open while it verifies the digest and publisher. Electron checks the active vault and profile before confirming the launch. The worker checks the managed approval again, resolves the verified file's volume path and starts the installer with read locks on the file and its parent directories. Those locks stay with the installer after Wormhole exits. Closing the verification channel before confirmation cancels the launch.

For a Paranoid machine, deploy the package and its matching [installation proof](vault-installation-proof.md) together before relaunch. On Windows, Wormhole passes the verified installer to Inno Setup and leaves the app closed so the administrator can deploy the proof. On Linux, install the managed package in the protected system location. Public Linux updates continue to use the AppImage.

## Windows release signing

The release job signs the x64 and ARM64 Inno Setup installers using a code-signing certificate in Azure Key Vault. Configure these GitHub Actions variables on the release repository.

| Variable                                                                      | Value                                                                                                 |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `WORMHOLE_WINDOWS_PUBLISHER_SPKI`                                             | Lowercase SHA-256 of the signing certificate's DER SubjectPublicKeyInfo, also embedded in the updater |
| `WORMHOLE_WINDOWS_KEY_VAULT_NAME`                                             | Name of the vault on `vault.azure.net`                                                                |
| `WORMHOLE_WINDOWS_KEY_VAULT_CERTIFICATE`                                      | Name of the code-signing certificate in that vault                                                    |
| `WORMHOLE_WINDOWS_SIGNING_TENANT_ID` and `WORMHOLE_WINDOWS_SIGNING_CLIENT_ID` | Tenant ID and application ID of the release signing identity                                          |

Store the application's credential in the Actions secret `WORMHOLE_WINDOWS_SIGNING_CLIENT_SECRET`. Give the identity access to read the named certificate and sign with its associated key. The signing step reads its credential from the environment. The private signing key stays in Key Vault. The workflow checks the SHA-256 of the signing tool against the published package digest. [AzureSignTool 7.0.1](https://github.com/vcsjones/AzureSignTool/tree/v7.0.1) · [WinGet package digest](https://github.com/microsoft/winget-pkgs/blob/master/manifests/v/vcsjones/AzureSignTool/7.0.1/vcsjones.AzureSignTool.installer.yaml)

The job requests a SHA-256 timestamp, verifies the finished installer with the same native verifier as the app and produces the checksum from those bytes. A signing or verification failure with a configured publisher stops publication. Production validation requires the signing service and its trusted code-signing certificate.
