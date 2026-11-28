# Signed per-machine installations

A Paranoid machine floor checks the running installation before Wormhole opens the vault. The installed files must have administrator-controlled permissions and match the detached Ed25519 proof for that release and architecture.

| Installation           | Release asset                                         | Destination beside the installed package |
| ---------------------- | ----------------------------------------------------- | ---------------------------------------- |
| Windows x64            | `Wormhole-InstallationProof-v1-windows-x64.json`      | `Wormhole.wh-installation.json`          |
| Windows ARM64          | `Wormhole-InstallationProof-v1-windows-arm64.json`    | `Wormhole.wh-installation.json`          |
| Linux x64 DEB or RPM   | `Wormhole-InstallationProof-v1-linux-x64.json`        | `Wormhole.wh-installation.json`          |
| Linux ARM64 DEB or RPM | `Wormhole-InstallationProof-v1-linux-arm64.json`      | `Wormhole.wh-installation.json`          |
| macOS universal        | `Wormhole-InstallationProof-v1-darwin-universal.json` | `Wormhole.app.wh-installation.json`      |

Use the package's actual directory name as the prefix and append `.wh-installation.json`. For example, install the macOS proof at `/Applications/Wormhole.app.wh-installation.json`. Keep the proof and package in an administrator-controlled location. Deploy both from the same release before starting Wormhole. When replacing the installation, close the app and deploy the replacement package and proof before relaunching it.

The release workflow measures the Windows staged installer payload, the Linux DEB and RPM payloads, and the app bundle in the macOS disk image. Linux package payloads for each architecture must match. The release signing job publishes each inventory and its signature together in a detached proof. Windows ACL checks still cover Inno Setup's numbered maintenance files. Those files are generated during installation and are outside the signed application inventory.

Use the manifest tool's `verify-installation` command with the release target, installed directory and pinned public key to check the payload before relaunching. A stale or modified file in the live application directory fails verification. A clean deployment into an administrator-controlled location provides a known starting tree.
