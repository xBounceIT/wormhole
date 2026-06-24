namespace Wormhole.Models;

public enum ProtocolType
{
    Ssh = 0,
    Rdp = 1,

    // Value 2 was the retired SFTP protocol. It is deliberately skipped rather than reused: migration
    // 0009 repairs Protocol=2 rows in the live DB, but a legacy *backup* file still carries 2, and the
    // import path normalizes any undefined protocol to SSH. Reusing 2 would silently turn those legacy
    // SFTP nodes into a web connection. New web protocols therefore start at 3.

    // Web protocols rendered in an embedded WebView2 browser surface. The enum value IS the scheme.
    Http = 3,
    Https = 4,

    // Local serial-port terminal sessions. Serial shipped on main as value 5, so keep it stable for
    // existing databases and backups.
    Serial = 5,

    // Embedded VNC client. Value 2 remains reserved for retired SFTP.
    Vnc = 6,
}
