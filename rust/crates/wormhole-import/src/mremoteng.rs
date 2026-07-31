//! mRemoteNG XML reader + import plan (SSH/RDP/VNC only).

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use uuid::Uuid;

use crate::crypto::decrypt_password_utf8;
use crate::error::ImportError;
use crate::limits::{read_file_capped, MAX_NODE_COUNT};
use crate::protocol::{map_protocol, MappedProtocol};

/// Cap matching C# `MRemoteNgXmlReader.MaxNestingDepth`.
pub const MAX_NESTING_DEPTH: usize = 4096;

/// mRemoteNG root `Protected` verifier plaintext (C# `ProtectedVerifier`).
pub const PROTECTED_VERIFIER: &str = "ThisIsProtected";

const MRNG_NS: &str = "http://mremoteng.org";

/// Root `<mrng:Connections>` attributes (Inspect / Plan metadata).
#[derive(Clone, PartialEq, Eq)]
pub struct MRemoteNgRoot {
    pub conf_version: String,
    pub encryption_engine: String,
    pub block_cipher_mode: String,
    pub protected: String,
    pub full_file_encryption: bool,
    pub kdf_iterations: i32,
}

impl fmt::Debug for MRemoteNgRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MRemoteNgRoot")
            .field("conf_version", &self.conf_version)
            .field("encryption_engine", &self.encryption_engine)
            .field("block_cipher_mode", &self.block_cipher_mode)
            .field(
                "protected",
                &if self.protected.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("full_file_encryption", &self.full_file_encryption)
            .field("kdf_iterations", &self.kdf_iterations)
            .finish()
    }
}

/// Lightweight inspect result (mirrors `MRemoteNgFileInfo`).
#[derive(Clone, PartialEq, Eq)]
pub struct MRemoteNgFileInfo {
    pub conf_version: String,
    pub encryption_engine: String,
    pub block_cipher_mode: String,
    pub protected: String,
    pub full_file_encryption: bool,
    pub kdf_iterations: i32,
    pub has_password_payloads: bool,
}

impl fmt::Debug for MRemoteNgFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MRemoteNgFileInfo")
            .field("conf_version", &self.conf_version)
            .field("encryption_engine", &self.encryption_engine)
            .field("block_cipher_mode", &self.block_cipher_mode)
            .field(
                "protected",
                &if self.protected.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("full_file_encryption", &self.full_file_encryption)
            .field("kdf_iterations", &self.kdf_iterations)
            .field("has_password_payloads", &self.has_password_payloads)
            .finish()
    }
}

impl From<&MRemoteNgRoot> for MRemoteNgFileInfo {
    fn from(root: &MRemoteNgRoot) -> Self {
        Self {
            conf_version: root.conf_version.clone(),
            encryption_engine: root.encryption_engine.clone(),
            block_cipher_mode: root.block_cipher_mode.clone(),
            protected: root.protected.clone(),
            full_file_encryption: root.full_file_encryption,
            kdf_iterations: root.kdf_iterations,
            has_password_payloads: false,
        }
    }
}

/// One raw `<Node>` with string attributes (no decrypt, no persistence).
#[derive(Clone, PartialEq, Eq)]
pub struct MRemoteNgRawNode {
    pub type_name: String,
    pub name: String,
    pub description: String,
    pub protocol: String,
    pub hostname: String,
    pub port: String,
    pub username: String,
    pub domain: String,
    pub password_cipher: String,
    pub resolution: String,
    pub inherit_username: bool,
    pub inherit_domain: bool,
    pub inherit_password: bool,
    pub inherit_hostname: bool,
    pub inherit_port: bool,
    pub inherit_protocol: bool,
    pub inherit_resolution: bool,
    pub children: Vec<MRemoteNgRawNode>,
}

impl fmt::Debug for MRemoteNgRawNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MRemoteNgRawNode")
            .field("type_name", &self.type_name)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("protocol", &self.protocol)
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field(
                "password_cipher",
                &if self.password_cipher.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("resolution", &self.resolution)
            .field("inherit_username", &self.inherit_username)
            .field("inherit_domain", &self.inherit_domain)
            .field("inherit_password", &self.inherit_password)
            .field("inherit_hostname", &self.inherit_hostname)
            .field("inherit_port", &self.inherit_port)
            .field("inherit_protocol", &self.inherit_protocol)
            .field("inherit_resolution", &self.inherit_resolution)
            .field("children", &self.children)
            .finish()
    }
}

/// Planned Wormhole-shaped node (folders + SSH/RDP/VNC).
///
/// Persist via [`crate::apply_import_plan`] (`storage` feature). Password plaintext
/// is planning-only until Credential Manager wiring lands.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedNode {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub is_folder: bool,
    pub protocol: Option<MappedProtocol>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub sort_order: i32,
    /// Present when decrypt succeeded; decrypt failure leaves this unset + a warning.
    pub password_plaintext: Option<String>,
    pub password_decrypt_failed: bool,
}

impl fmt::Debug for PlannedNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedNode")
            .field("id", &self.id)
            .field("parent_id", &self.parent_id)
            .field("name", &self.name)
            .field("is_folder", &self.is_folder)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("sort_order", &self.sort_order)
            .field(
                "password_plaintext",
                &self.password_plaintext.as_ref().map(|_| "[REDACTED]"),
            )
            .field("password_decrypt_failed", &self.password_decrypt_failed)
            .finish()
    }
}

/// Result of [`plan_nodes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    pub nodes: Vec<PlannedNode>,
    pub folder_count: usize,
    pub connection_count: usize,
    pub skipped: usize,
    pub skipped_samples: Vec<String>,
    pub warnings: Vec<String>,
}

/// Parse an mRemoteNG export from bytes / any `Read`.
pub fn parse_xml(reader: impl Read) -> Result<(MRemoteNgRoot, Vec<MRemoteNgRawNode>), ImportError> {
    let mut bytes = Vec::new();
    let mut reader = reader;
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > crate::limits::MAX_IMPORT_FILE_BYTES {
        return Err(ImportError::InvalidData(format!(
            "XML is {} bytes; refusing anything larger than {} bytes",
            bytes.len(),
            crate::limits::MAX_IMPORT_FILE_BYTES
        )));
    }
    parse_xml_bytes(&bytes)
}

/// Parse from file path (size-capped; rejects `..` / NUL).
pub fn parse_xml_path(
    path: impl AsRef<Path>,
) -> Result<(MRemoteNgRoot, Vec<MRemoteNgRawNode>), ImportError> {
    let bytes = read_file_capped(path.as_ref())?;
    parse_xml_bytes(&bytes)
}

/// Parse from an in-memory buffer.
pub fn parse_xml_bytes(
    bytes: &[u8],
) -> Result<(MRemoteNgRoot, Vec<MRemoteNgRawNode>), ImportError> {
    if bytes.len() as u64 > crate::limits::MAX_IMPORT_FILE_BYTES {
        return Err(ImportError::InvalidData(format!(
            "XML is {} bytes; refusing anything larger than {} bytes",
            bytes.len(),
            crate::limits::MAX_IMPORT_FILE_BYTES
        )));
    }

    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut root: Option<MRemoteNgRoot> = None;
    let mut stack: Vec<MRemoteNgRawNode> = Vec::new();
    let mut roots: Vec<MRemoteNgRawNode> = Vec::new();
    let mut node_depth: usize = 0;
    let mut node_count: usize = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                handle_element(
                    &e,
                    false,
                    &mut root,
                    &mut stack,
                    &mut roots,
                    &mut node_depth,
                    &mut node_count,
                )?;
            }
            Ok(Event::Empty(e)) => {
                handle_element(
                    &e,
                    true,
                    &mut root,
                    &mut stack,
                    &mut roots,
                    &mut node_depth,
                    &mut node_count,
                )?;
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "Node" {
                    finish_node(&mut stack, &mut roots)?;
                    node_depth = node_depth.saturating_sub(1);
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(ImportError::InvalidData(
                    "DOCTYPE / DTD is not allowed in mRemoteNG imports (XXE protection)".into(),
                ));
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(ImportError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    if !stack.is_empty() {
        return Err(ImportError::InvalidData(
            "unbalanced <Node> elements (malformed tree)".into(),
        ));
    }

    let root = root.ok_or_else(|| {
        ImportError::InvalidData(
            "Root element is not <mrng:Connections>. This does not look like an mRemoteNG export."
                .into(),
        )
    })?;
    Ok((root, roots))
}

fn handle_element(
    e: &quick_xml::events::BytesStart<'_>,
    empty: bool,
    root: &mut Option<MRemoteNgRoot>,
    stack: &mut Vec<MRemoteNgRawNode>,
    roots: &mut Vec<MRemoteNgRawNode>,
    node_depth: &mut usize,
    node_count: &mut usize,
) -> Result<(), ImportError> {
    let local = local_name(e.name().as_ref());
    if local == "Connections" {
        if root.is_some() {
            return Err(ImportError::InvalidData(
                "multiple <mrng:Connections> roots".into(),
            ));
        }
        validate_connections_ns(e)?;
        let attrs = collect_attrs(e)?;
        *root = Some(MRemoteNgRoot {
            conf_version: attrs.get("ConfVersion").cloned().unwrap_or_default(),
            encryption_engine: attrs.get("EncryptionEngine").cloned().unwrap_or_default(),
            block_cipher_mode: attrs.get("BlockCipherMode").cloned().unwrap_or_default(),
            protected: attrs.get("Protected").cloned().unwrap_or_default(),
            full_file_encryption: attr_bool(attrs.get("FullFileEncryption")),
            kdf_iterations: parse_int_positive(
                attrs.get("KdfIterations").map(String::as_str),
                1000,
            ),
        });
        return Ok(());
    }

    if local != "Node" {
        return Ok(());
    }

    *node_count += 1;
    if *node_count > MAX_NODE_COUNT {
        return Err(ImportError::InvalidData(format!(
            "mRemoteNG node count exceeds {MAX_NODE_COUNT}; refusing to import."
        )));
    }

    *node_depth += 1;
    if *node_depth > MAX_NESTING_DEPTH {
        return Err(ImportError::InvalidData(format!(
            "mRemoteNG nesting depth exceeds {MAX_NESTING_DEPTH}; refusing to import."
        )));
    }

    let attrs = collect_attrs(e)?;
    stack.push(build_raw_node(attrs));
    if empty {
        finish_node(stack, roots)?;
        *node_depth = node_depth.saturating_sub(1);
    }
    Ok(())
}

fn validate_connections_ns(e: &quick_xml::events::BytesStart<'_>) -> Result<(), ImportError> {
    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref());
        if key == "xmlns:mrng" || key == "xmlns" {
            #[allow(deprecated)]
            let val = attr.unescape_value().unwrap_or_default();
            if &*val == MRNG_NS {
                return Ok(());
            }
        }
    }
    if e.name().prefix().is_some_and(|p| p.as_ref() == b"mrng") {
        return Ok(());
    }
    Err(ImportError::InvalidData(
        "Root element is not <mrng:Connections>. This does not look like an mRemoteNG export."
            .into(),
    ))
}

fn build_raw_node(attrs: HashMap<String, String>) -> MRemoteNgRawNode {
    MRemoteNgRawNode {
        type_name: attrs.get("Type").cloned().unwrap_or_default(),
        name: attrs.get("Name").cloned().unwrap_or_default(),
        description: attrs
            .get("Descr")
            .or_else(|| attrs.get("Description"))
            .cloned()
            .unwrap_or_default(),
        protocol: attrs.get("Protocol").cloned().unwrap_or_default(),
        hostname: attrs.get("Hostname").cloned().unwrap_or_default(),
        port: attrs.get("Port").cloned().unwrap_or_default(),
        username: attrs.get("Username").cloned().unwrap_or_default(),
        domain: attrs.get("Domain").cloned().unwrap_or_default(),
        password_cipher: attrs.get("Password").cloned().unwrap_or_default(),
        resolution: attrs.get("Resolution").cloned().unwrap_or_default(),
        inherit_username: attr_bool(attrs.get("InheritUsername")),
        inherit_domain: attr_bool(attrs.get("InheritDomain")),
        inherit_password: attr_bool(attrs.get("InheritPassword")),
        inherit_hostname: attr_bool(attrs.get("InheritHostname")),
        inherit_port: attr_bool(attrs.get("InheritPort")),
        inherit_protocol: attr_bool(attrs.get("InheritProtocol")),
        inherit_resolution: attr_bool(attrs.get("InheritResolution")),
        children: Vec::new(),
    }
}

fn finish_node(
    stack: &mut Vec<MRemoteNgRawNode>,
    roots: &mut Vec<MRemoteNgRawNode>,
) -> Result<(), ImportError> {
    let finished = stack
        .pop()
        .ok_or_else(|| ImportError::InvalidData("unbalanced </Node>".into()))?;
    if let Some(parent) = stack.last_mut() {
        parent.children.push(finished);
    } else {
        roots.push(finished);
    }
    Ok(())
}

fn local_name(name: &[u8]) -> String {
    let s = String::from_utf8_lossy(name);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.into_owned(),
    }
}

fn collect_attrs(
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<HashMap<String, String>, ImportError> {
    let mut map = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| ImportError::Xml(err.to_string()))?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let key = match key.rsplit_once(':') {
            Some((_, local)) => local.to_string(),
            None => key,
        };
        #[allow(deprecated)]
        let val = attr
            .unescape_value()
            .map_err(|err| ImportError::Xml(err.to_string()))?
            .into_owned();
        map.insert(key, val);
    }
    Ok(map)
}

fn attr_bool(raw: Option<&String>) -> bool {
    raw.is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn parse_int_positive(raw: Option<&str>, fallback: i32) -> i32 {
    raw.and_then(|s| s.parse::<i32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(fallback)
}

fn null_if_empty(value: &str) -> Option<String> {
    let t = value.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn password_requires_decrypt(cipher: &str, inherit_password: bool) -> bool {
    !inherit_password && !cipher.trim().is_empty()
}

/// Inspect file path: root attributes + whether any non-inherited Password exists.
pub fn inspect_xml(path: impl AsRef<Path>) -> Result<MRemoteNgFileInfo, ImportError> {
    let bytes = read_file_capped(path.as_ref())?;
    let (root, nodes) = parse_xml_bytes(&bytes)?;
    let mut info = MRemoteNgFileInfo::from(&root);
    info.has_password_payloads = nodes.iter().any(subtree_has_password);
    Ok(info)
}

fn subtree_has_password(node: &MRemoteNgRawNode) -> bool {
    if password_requires_decrypt(&node.password_cipher, node.inherit_password) {
        return true;
    }
    node.children.iter().any(subtree_has_password)
}

/// Plan folders + SSH/RDP/VNC connections. Skips unsupported Connection protocols.
///
/// `import_password` decrypts non-empty `Password` attributes via
/// [`crate::decrypt_password_utf8`]. Failures leave the credential unset and add a warning.
pub fn plan_nodes(
    roots: &[MRemoteNgRawNode],
    root_meta: &MRemoteNgRoot,
    import_password: &str,
) -> Result<ImportPlan, ImportError> {
    let mut nodes = Vec::new();
    let mut folder_count = 0usize;
    let mut connection_count = 0usize;
    let mut skipped = 0usize;
    let mut skipped_samples = Vec::new();
    let mut warnings = Vec::new();

    for (i, raw) in roots.iter().enumerate() {
        walk(
            raw,
            None,
            i as i32,
            1,
            root_meta,
            import_password,
            &mut nodes,
            &mut folder_count,
            &mut connection_count,
            &mut skipped,
            &mut skipped_samples,
            &mut warnings,
        )?;
    }

    Ok(ImportPlan {
        nodes,
        folder_count,
        connection_count,
        skipped,
        skipped_samples,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk(
    raw: &MRemoteNgRawNode,
    parent_id: Option<Uuid>,
    sort_order: i32,
    depth: usize,
    root_meta: &MRemoteNgRoot,
    import_password: &str,
    out: &mut Vec<PlannedNode>,
    folder_count: &mut usize,
    connection_count: &mut usize,
    skipped: &mut usize,
    skipped_samples: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<(), ImportError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(ImportError::InvalidData(format!(
            "mRemoteNG nesting depth exceeds {MAX_NESTING_DEPTH}; refusing to import."
        )));
    }

    let is_container = raw.type_name.eq_ignore_ascii_case("Container");
    let is_connection = raw.type_name.eq_ignore_ascii_case("Connection");
    if !is_container && !is_connection {
        return Ok(());
    }

    // Soft-skip Connection leaves with unmapped protocols (HTTP / HTTPS / Serial / …).
    // Same classification as `try_map_protocol` → UnsupportedProtocol; planning does not
    // abort the whole import for those leaves (C# TryMapProtocol false → skip).
    let mapped = match map_protocol(&raw.protocol) {
        Some(p) => Some(p),
        None if is_connection => {
            *skipped += 1;
            if skipped_samples.len() < 5 {
                let trimmed = raw.protocol.trim();
                let display = if trimmed.is_empty() {
                    "(unspecified)"
                } else {
                    trimmed
                };
                skipped_samples.push(format!("{}: {display}", raw.name));
            }
            return Ok(());
        }
        None => None,
    };
    let mut protocol = mapped;

    if raw.inherit_protocol {
        protocol = None;
    }

    let username = if raw.inherit_username {
        None
    } else {
        null_if_empty(&raw.username)
    };
    let domain = if raw.inherit_domain {
        None
    } else {
        null_if_empty(&raw.domain)
    };
    let host = if raw.inherit_hostname {
        None
    } else {
        null_if_empty(&raw.hostname)
    };
    let port = if raw.inherit_port {
        None
    } else {
        parse_port(&raw.port)
    };

    // VNC: username/domain unused in Wormhole v1.
    let (username, domain) = if mapped == Some(MappedProtocol::Vnc) {
        (None, None)
    } else {
        (username, domain)
    };

    let mut password_plaintext = None;
    let mut password_decrypt_failed = false;
    if password_requires_decrypt(&raw.password_cipher, raw.inherit_password) {
        match decrypt_password_utf8(&raw.password_cipher, import_password, root_meta.kdf_iterations)
        {
            Ok(Some(p)) if !p.is_empty() => password_plaintext = Some(p),
            Ok(_) => {}
            Err(_) => {
                password_decrypt_failed = true;
                let display = if raw.name.trim().is_empty() {
                    "(unnamed)"
                } else {
                    raw.name.as_str()
                };
                warnings.push(format!(
                    "Could not decrypt password for '{display}'; credential left unset \
                     (wrong import password or malformed ciphertext)."
                ));
            }
        }
    }

    let id = Uuid::new_v4();
    let name = if raw.name.trim().is_empty() {
        if is_container {
            "Folder".into()
        } else {
            host.clone().unwrap_or_else(|| "Connection".into())
        }
    } else {
        raw.name.clone()
    };

    out.push(PlannedNode {
        id,
        parent_id,
        name,
        is_folder: is_container,
        protocol,
        host,
        port,
        username,
        domain,
        sort_order,
        password_plaintext,
        password_decrypt_failed,
    });

    if is_container {
        *folder_count += 1;
        for (i, child) in raw.children.iter().enumerate() {
            walk(
                child,
                Some(id),
                i as i32,
                depth + 1,
                root_meta,
                import_password,
                out,
                folder_count,
                connection_count,
                skipped,
                skipped_samples,
                warnings,
            )?;
        }
    } else {
        *connection_count += 1;
    }

    Ok(())
}

fn parse_port(raw: &str) -> Option<i32> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<i32>().ok().filter(|&p| p > 0 && p <= 65535)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::try_map_protocol;

    #[test]
    fn rejects_doctype_xxe() {
        let xml = br#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000"/>"#;
        let err = parse_xml_bytes(xml).unwrap_err();
        assert!(
            err.to_string().contains("DOCTYPE") || err.to_string().contains("DTD"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unbalanced_node() {
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="Lab" Type="Container" Protocol="SSH2">
</mrng:Connections>"#;
        let err = parse_xml_bytes(xml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unbalanced") || msg.contains("XML") || msg.contains("malformed"),
            "{msg}"
        );
    }

    #[test]
    fn planned_node_debug_redacts_password() {
        let node = PlannedNode {
            id: Uuid::nil(),
            parent_id: None,
            name: "x".into(),
            is_folder: false,
            protocol: Some(MappedProtocol::Ssh),
            host: Some("h".into()),
            port: Some(22),
            username: None,
            domain: None,
            sort_order: 0,
            password_plaintext: Some("LITERAL_SECRET".into()),
            password_decrypt_failed: false,
        };
        let dbg = format!("{node:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("LITERAL_SECRET"), "{dbg}");
    }

    /// Planned nodes must never carry Wormhole Http/Https/Serial — those mRemoteNG
    /// leaves are soft-skipped, not remapped (e.g. HTTP must not become SSH).
    fn assert_no_gap_protocol_mapping(plan: &ImportPlan) {
        for n in &plan.nodes {
            assert!(
                matches!(
                    n.protocol,
                    None
                        | Some(MappedProtocol::Ssh)
                        | Some(MappedProtocol::Rdp)
                        | Some(MappedProtocol::Vnc)
                ),
                "planned node '{}' must not map to Http/Https/Serial (got {:?})",
                n.name,
                n.protocol
            );
        }
    }

    #[test]
    fn soft_skips_http_https_serial_connection_leaves() {
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="gap-folder" Type="Container" Protocol="SSH2">
    <Node Name="web-http" Type="Connection" Protocol="HTTP"
          Hostname="192.0.2.41" Port="80" Username="" Password="" />
    <Node Name="web-https" Type="Connection" Protocol="HTTPS"
          Hostname="192.0.2.42" Port="443" Username="" Password="" />
    <Node Name="console-serial" Type="Connection" Protocol="Serial"
          Hostname="COM4" Port="" Username="" Password="" />
    <Node Name="keep-ssh" Type="Connection" Protocol="SSH2"
          Hostname="192.0.2.10" Port="22" Username="u" Password="" />
  </Node>
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("plan must not abort on soft-skip");
        assert_eq!(plan.folder_count, 1);
        assert_eq!(plan.connection_count, 1);
        assert_eq!(plan.skipped, 3);
        assert!(plan.skipped_samples.iter().any(|s| s.contains("HTTP")));
        assert!(plan.skipped_samples.iter().any(|s| s.contains("HTTPS")));
        assert!(plan.skipped_samples.iter().any(|s| s.contains("Serial")));
        assert!(!plan.nodes.iter().any(|n| n.name == "web-http"));
        assert!(!plan.nodes.iter().any(|n| n.name == "web-https"));
        assert!(!plan.nodes.iter().any(|n| n.name == "console-serial"));
        assert!(plan.nodes.iter().any(|n| {
            n.name == "keep-ssh" && n.protocol == Some(MappedProtocol::Ssh) && !n.is_folder
        }));
        assert_no_gap_protocol_mapping(&plan);

        // Explicit classification for the gap protocols (not mapped; not silent None-only).
        for raw in ["HTTP", "HTTPS", "Serial"] {
            match try_map_protocol(raw) {
                Err(ImportError::UnsupportedProtocol(label)) => assert_eq!(label, raw),
                other => panic!("expected UnsupportedProtocol for {raw}, got {other:?}"),
            }
        }
    }

    #[test]
    fn soft_skips_telnet_and_raw_without_aborting_siblings() {
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="mixed" Type="Container" Protocol="SSH2">
    <Node Name="legacy-telnet" Type="Connection" Protocol="TELNET"
          Hostname="192.0.2.60" Port="23" Username="" Password="" />
    <Node Name="raw-pipe" Type="Connection" Protocol="RAW"
          Hostname="192.0.2.61" Port="1" Username="" Password="" />
    <Node Name="keep-rdp" Type="Connection" Protocol="RDP"
          Hostname="192.0.2.20" Port="3389" Username="a" Domain="LAB" Password="" />
  </Node>
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("Telnet/RAW must soft-skip, not abort");
        assert_eq!(plan.folder_count, 1);
        assert_eq!(plan.connection_count, 1);
        assert_eq!(plan.skipped, 2);
        assert!(plan.skipped_samples.iter().any(|s| s.contains("TELNET")));
        assert!(plan.skipped_samples.iter().any(|s| s.contains("RAW")));
        assert!(!plan.nodes.iter().any(|n| n.name == "legacy-telnet"));
        assert!(!plan.nodes.iter().any(|n| n.name == "raw-pipe"));
        assert!(plan.nodes.iter().any(|n| {
            n.name == "keep-rdp" && n.protocol == Some(MappedProtocol::Rdp) && !n.is_folder
        }));
        assert_no_gap_protocol_mapping(&plan);
    }

    #[test]
    fn container_unmapped_protocol_still_plans_ssh_children() {
        // Containers with weird Protocol become folders with protocol=None; children still walk.
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="http-shaped-folder" Type="Container" Protocol="HTTP">
    <Node Name="child-ssh" Type="Connection" Protocol="SSH2"
          Hostname="192.0.2.10" Port="22" Username="u" Password="" />
  </Node>
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("plan");
        assert_eq!(plan.skipped, 0);
        assert_eq!(plan.folder_count, 1);
        assert_eq!(plan.connection_count, 1);
        let folder = plan
            .nodes
            .iter()
            .find(|n| n.name == "http-shaped-folder")
            .expect("folder");
        assert!(folder.is_folder);
        assert_eq!(folder.protocol, None);
        assert!(plan.nodes.iter().any(|n| {
            n.name == "child-ssh" && n.protocol == Some(MappedProtocol::Ssh) && !n.is_folder
        }));
        assert_no_gap_protocol_mapping(&plan);
    }

    #[test]
    fn all_unsupported_connections_plan_succeeds_empty() {
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="only-http" Type="Connection" Protocol="HTTP"
        Hostname="192.0.2.41" Port="80" Username="" Password="" />
  <Node Name="only-telnet" Type="Connection" Protocol="Telnet"
        Hostname="192.0.2.60" Port="23" Username="" Password="" />
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("all-unsupported must not fail the plan");
        assert_eq!(plan.connection_count, 0);
        assert_eq!(plan.folder_count, 0);
        assert_eq!(plan.skipped, 2);
        assert!(plan.nodes.is_empty());
        assert!(plan.skipped_samples.iter().any(|s| s.contains("HTTP")));
        assert!(plan.skipped_samples.iter().any(|s| s.contains("Telnet")));
    }

    #[test]
    fn soft_skips_empty_protocol_as_unspecified_sample() {
        // C# parity: empty Protocol → skip sample label "(unspecified)".
        let xml = br#"<?xml version="1.0"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.7"
 EncryptionEngine="AES" BlockCipherMode="GCM" Protected="" FullFileEncryption="false"
 KdfIterations="1000">
  <Node Name="mystery" Type="Connection" Protocol=""
        Hostname="192.0.2.99" Port="1" Username="" Password="" />
  <Node Name="keep-vnc" Type="Connection" Protocol="VNC"
        Hostname="192.0.2.30" Port="5900" Username="" Password="" />
</mrng:Connections>"#;
        let (root, nodes) = parse_xml_bytes(xml).expect("parse");
        let plan = plan_nodes(&nodes, &root, "").expect("empty protocol soft-skips");
        assert_eq!(plan.skipped, 1);
        assert_eq!(plan.connection_count, 1);
        assert!(
            plan.skipped_samples.iter().any(|s| s == "mystery: (unspecified)"),
            "{:?}",
            plan.skipped_samples
        );
        assert!(plan.nodes.iter().any(|n| {
            n.name == "keep-vnc" && n.protocol == Some(MappedProtocol::Vnc)
        }));
        assert_no_gap_protocol_mapping(&plan);
    }

    #[test]
    fn parse_path_rejects_parent_components() {
        let err = parse_xml_path(Path::new("..\\evil.xml")).unwrap_err();
        assert!(
            err.to_string().contains("..") || err.to_string().contains("path"),
            "{err}"
        );
    }
}
