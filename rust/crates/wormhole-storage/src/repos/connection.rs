//! Connection / folder repository (read + write).
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, CredentialBindingMode, NodeKind, ProtocolType, SerialFlowControlMode,
    SerialParityMode, SerialStopBitsMode,
};

use crate::models::StoredConnectionNode;
use crate::types::{format_guid_d, format_timestamp_o, parse_guid_d, parse_timestamp_o};
use crate::{Result, SqliteConnectionFactory, StorageError};

/// Canonical SELECT column list -- mirrors C# `ConnectionRepository.Columns`.
const SELECT_COLUMNS: &str = "\
Id, ParentId, Name, Kind, SortOrder, \
Protocol, Host, Port, Username, CredentialId, CredentialMode, UseInlinePassword, \
RdpDomain, RdpScreenSize, RdpFullScreen, \
RdpColorDepth, RdpUseAllMonitors, \
RdpAudioMode, RdpAudioCaptureMode, RdpKeyboardHookMode, \
RdpRedirectClipboard, RdpRedirectPrinters, RdpRedirectSmartCards, \
RdpRedirectPorts, RdpRedirectDevices, RdpRedirectDrives, \
RdpConnectionSpeed, RdpDesktopBackground, RdpFontSmoothing, \
RdpDesktopComposition, RdpWindowDrag, RdpMenuAnimation, \
RdpVisualStyles, RdpBitmapCaching, RdpAutoReconnect, \
RdpServerAuthentication, RdpGatewayUsageMethod, RdpGatewayHostname, \
RdpGatewayCredentialId, RdpGatewayBypassLocal, RdpGatewayUseSameCreds, \
RdpUseExternalClient, \
SshKeyFileName, SshKnownHostFingerprint, SshAutoSudo, \
SerialBaudRate, SerialDataBits, SerialStopBits, SerialParity, SerialFlowControl, \
HttpIgnoreCertErrors, \
TunnelEnabled, TunnelConfigId, \
CreatedAt, UpdatedAt";

/// UPDATE SET list -- every column except Id / CreatedAt (C# `UpdateExcluded`).
const UPDATE_ASSIGNMENTS: &str = "\
ParentId = ?2, Name = ?3, Kind = ?4, SortOrder = ?5, \
Protocol = ?6, Host = ?7, Port = ?8, Username = ?9, CredentialId = ?10, CredentialMode = ?11, UseInlinePassword = ?12, \
RdpDomain = ?13, RdpScreenSize = ?14, RdpFullScreen = ?15, \
RdpColorDepth = ?16, RdpUseAllMonitors = ?17, \
RdpAudioMode = ?18, RdpAudioCaptureMode = ?19, RdpKeyboardHookMode = ?20, \
RdpRedirectClipboard = ?21, RdpRedirectPrinters = ?22, RdpRedirectSmartCards = ?23, \
RdpRedirectPorts = ?24, RdpRedirectDevices = ?25, RdpRedirectDrives = ?26, \
RdpConnectionSpeed = ?27, RdpDesktopBackground = ?28, RdpFontSmoothing = ?29, \
RdpDesktopComposition = ?30, RdpWindowDrag = ?31, RdpMenuAnimation = ?32, \
RdpVisualStyles = ?33, RdpBitmapCaching = ?34, RdpAutoReconnect = ?35, \
RdpServerAuthentication = ?36, RdpGatewayUsageMethod = ?37, RdpGatewayHostname = ?38, \
RdpGatewayCredentialId = ?39, RdpGatewayBypassLocal = ?40, RdpGatewayUseSameCreds = ?41, \
RdpUseExternalClient = ?42, \
SshKeyFileName = ?43, SshKnownHostFingerprint = ?44, SshAutoSudo = ?45, \
SerialBaudRate = ?46, SerialDataBits = ?47, SerialStopBits = ?48, SerialParity = ?49, SerialFlowControl = ?50, \
HttpIgnoreCertErrors = ?51, \
TunnelEnabled = ?52, TunnelConfigId = ?53, \
UpdatedAt = ?54";

/// Access to the `Nodes` table (folders + connections).
pub struct ConnectionRepository<'a> {
    factory: &'a SqliteConnectionFactory,
}
impl<'a> ConnectionRepository<'a> {
    pub fn new(factory: &'a SqliteConnectionFactory) -> Self {
        Self { factory }
    }
    /// All nodes ordered by `ParentId, SortOrder, Name` (same as C# `GetAllAsync`).
    pub fn list_all(&self) -> Result<Vec<StoredConnectionNode>> {
        let conn = self.factory.open()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM Nodes ORDER BY ParentId, SortOrder, Name;");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], map_stored_node)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Folder nodes only (`Kind = 0`), same ordering as [`list_all`].
    pub fn list_folders(&self) -> Result<Vec<StoredConnectionNode>> {
        self.list_by_kind(NodeKind::Folder)
    }
    /// Connection nodes only (`Kind = 1`).
    pub fn list_connections(&self) -> Result<Vec<StoredConnectionNode>> {
        self.list_by_kind(NodeKind::Connection)
    }
    fn list_by_kind(&self, kind: NodeKind) -> Result<Vec<StoredConnectionNode>> {
        let conn = self.factory.open()?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM Nodes WHERE Kind = ?1 ORDER BY ParentId, SortOrder, Name;"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([kind as i32], map_stored_node)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Lookup by primary key (format-`D` GUID string in SQLite).
    ///
    /// Comparison is ASCII case-insensitive: format `D` hex is case-insensitive, and
    /// hand-edited DBs may store uppercase even though writers emit lowercase.
    pub fn get_by_id(&self, id: Uuid) -> Result<Option<StoredConnectionNode>> {
        let conn = self.factory.open()?;
        get_by_id_on(&conn, id)
    }
    /// Insert a folder or connection node. Sets `CreatedAt` / `UpdatedAt` to UTC now (format `O`).
    ///
    /// GUID columns are written as lowercase format `D`. Foreign keys are enforced
    /// (`ParentId` must exist or be NULL).
    pub fn insert(&self, node: &ConnectionNode) -> Result<StoredConnectionNode> {
        let now = Utc::now();
        let conn = self.factory.open()?;
        insert_on(&conn, node, now)?;
        Ok(StoredConnectionNode {
            node: node.clone(),
            created_at: now,
            updated_at: now,
        })
    }
    /// Insert many nodes in one transaction (shared `CreatedAt` / `UpdatedAt`).
    ///
    /// Callers must supply rows in parent-before-child order so `ParentId` FKs succeed
    /// (mRemoteNG import plans are DFS top-down). Empty slice is a no-op. On any
    /// failure the whole batch rolls back — not per-row commit.
    pub fn insert_many(&self, nodes: &[ConnectionNode]) -> Result<Vec<StoredConnectionNode>> {
        if nodes.is_empty() {
            return Ok(Vec::new());
        }
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction()?;
        for node in nodes {
            insert_on(&tx, node, now)?;
        }
        tx.commit()?;
        Ok(nodes
            .iter()
            .map(|node| StoredConnectionNode {
                node: node.clone(),
                created_at: now,
                updated_at: now,
            })
            .collect())
    }
    /// Update a node. Bumps `UpdatedAt`; leaves `CreatedAt` / `Id` unchanged.
    pub fn update(&self, node: &ConnectionNode) -> Result<()> {
        let now = Utc::now();
        let conn = self.factory.open()?;
        update_on(&conn, node, now)
    }
    /// Update many nodes in one transaction (shared `UpdatedAt`).
    pub fn update_many(&self, nodes: &[ConnectionNode]) -> Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction()?;
        for node in nodes {
            update_on(&tx, node, now)?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Delete a single node (cascades to children via `ON DELETE CASCADE`).
    pub fn delete(&self, id: Uuid) -> Result<()> {
        self.delete_many(&[id])
    }
    /// Delete many nodes in one transaction.
    pub fn delete_many(&self, ids: &[Uuid]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.factory.open()?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare("DELETE FROM Nodes WHERE Id = ?1 COLLATE NOCASE;")?;
            for id in ids {
                stmt.execute(params![format_guid_d(*id)])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Patch `SshKnownHostFingerprint` and bump `UpdatedAt` (C# `UpdateHostFingerprintAsync`).
    pub fn update_host_fingerprint(&self, node_id: Uuid, fingerprint: &str) -> Result<()> {
        if node_id.is_nil() {
            return Err(StorageError::InvalidArgument(
                "nodeId must not be empty".into(),
            ));
        }
        if fingerprint.trim().is_empty() {
            return Err(StorageError::InvalidArgument(
                "fingerprint must be a non-empty string".into(),
            ));
        }
        let now = format_timestamp_o(Utc::now());
        let conn = self.factory.open()?;
        conn.execute(
            "UPDATE Nodes SET SshKnownHostFingerprint = ?1, UpdatedAt = ?2 WHERE Id = ?3 COLLATE NOCASE;",
            params![fingerprint, now, format_guid_d(node_id)],
        )?;
        Ok(())
    }

    // --- Tree CRUD helpers (folders + connection reparent stub) ---

    /// Create a folder under `parent_id` (`None` = root). Assigns a fresh id and next
    /// `SortOrder` among siblings. Folder rows carry **no secrets** — only Name / ParentId /
    /// Kind / SortOrder (plus optional inherit fields left `None`).
    ///
    /// Mirrors C# `AddFolder` seed → `AddAsync` (dialog supplies the name). Parent must be a
    /// folder when set (`InheritanceResolver` walks `ParentId`). Parent check, `SortOrder`
    /// allocation, and insert run in one `IMMEDIATE` transaction so concurrent creates do not
    /// race on the same sibling max.
    pub fn create_folder(&self, name: &str, parent_id: Option<Uuid>) -> Result<StoredConnectionNode> {
        let name = require_nonblank_name(name)?;
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(parent) = parent_id {
            require_folder_on(&tx, parent)?;
        }
        let sort_order = next_sort_order_on(&tx, parent_id)?;
        let node = ConnectionNode {
            id: Uuid::new_v4(),
            parent_id,
            name,
            kind: NodeKind::Folder,
            sort_order,
            ..ConnectionNode::default()
        };
        insert_on(&tx, &node, now)?;
        tx.commit()?;
        Ok(StoredConnectionNode {
            node,
            created_at: now,
            updated_at: now,
        })
    }

    /// Rename an existing folder. Rejects blank names and non-folder targets.
    pub fn rename_folder(&self, folder_id: Uuid, name: &str) -> Result<StoredConnectionNode> {
        let name = require_nonblank_name(name)?;
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = require_folder_on(&tx, folder_id)?;
        stored.node.name = name;
        update_on(&tx, &stored.node, now)?;
        tx.commit()?;
        Ok(StoredConnectionNode {
            node: stored.node,
            created_at: stored.created_at,
            updated_at: now,
        })
    }

    /// Delete a folder node. Cascades to descendants via schema `ON DELETE CASCADE`
    /// (same as generic [`delete`]). Rejects non-folder targets.
    pub fn delete_folder(&self, folder_id: Uuid) -> Result<()> {
        let mut conn = self.factory.open()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_folder_on(&tx, folder_id)?;
        tx.execute(
            "DELETE FROM Nodes WHERE Id = ?1 COLLATE NOCASE;",
            params![format_guid_d(folder_id)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Move/reparent stub: set a **connection** node's `ParentId` to a folder (or root).
    ///
    /// Appends under the new parent (`SortOrder` = next sibling). Does **not** implement
    /// full drag-drop sibling reorder / folder-into-folder moves
    /// (`PersistTreeStructureAsync` stays UI-side). Rejects connection-as-parent so
    /// `InheritanceResolver` assumptions stay intact. Kind / parent checks, `SortOrder`
    /// allocation, and update share one `IMMEDIATE` transaction.
    pub fn reparent_connection(
        &self,
        connection_id: Uuid,
        new_parent_folder_id: Option<Uuid>,
    ) -> Result<StoredConnectionNode> {
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = get_by_id_on(&tx, connection_id)?
            .ok_or(StorageError::NotFound(connection_id))?;
        if stored.node.kind != NodeKind::Connection {
            return Err(StorageError::InvalidArgument(
                "reparent_connection requires a connection node".into(),
            ));
        }
        if let Some(parent) = new_parent_folder_id {
            if parent == connection_id {
                return Err(StorageError::InvalidArgument(
                    "connection cannot be its own parent".into(),
                ));
            }
            require_folder_on(&tx, parent)?;
        }
        if stored.node.parent_id == new_parent_folder_id {
            return Ok(stored);
        }
        stored.node.parent_id = new_parent_folder_id;
        stored.node.sort_order = next_sort_order_on(&tx, new_parent_folder_id)?;
        update_on(&tx, &stored.node, now)?;
        tx.commit()?;
        Ok(StoredConnectionNode {
            node: stored.node,
            created_at: stored.created_at,
            updated_at: now,
        })
    }

    /// Next `SortOrder` under `parent_id` (max sibling + 1, or 0 when empty).
    pub fn next_sort_order(&self, parent_id: Option<Uuid>) -> Result<i32> {
        let conn = self.factory.open()?;
        next_sort_order_on(&conn, parent_id)
    }

    /// Duplicate a **connection** under the same parent (C# tree Duplicate).
    ///
    /// Fresh Id via [`ConnectionNode::clone_as_new_identity`], name `"{name} (copy)"`,
    /// append `SortOrder`. Clears host-scoped fingerprint + inline-password flag — **never**
    /// copies CredMgr/DPAPI secret bodies into SQLite. Shared pool ids (`CredentialId` /
    /// `TunnelConfigId` / gateway credential) are preserved by design. Folders →
    /// [`StorageError::InvalidArgument`]; missing → [`StorageError::NotFound`].
    pub fn duplicate_connection(&self, source_id: Uuid) -> Result<StoredConnectionNode> {
        let now = Utc::now();
        let mut conn = self.factory.open()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source = get_by_id_on(&tx, source_id)?
            .ok_or(StorageError::NotFound(source_id))?;
        if source.node.kind != NodeKind::Connection {
            return Err(StorageError::InvalidArgument(
                "duplicate_connection requires a connection node".into(),
            ));
        }
        let mut node = source.node.clone_as_new_identity();
        node.name = format!("{} (copy)", source.node.name);
        node.parent_id = source.node.parent_id;
        node.sort_order = next_sort_order_on(&tx, source.node.parent_id)?;
        insert_on(&tx, &node, now)?;
        tx.commit()?;
        Ok(StoredConnectionNode {
            node,
            created_at: now,
            updated_at: now,
        })
    }
}

fn get_by_id_on(conn: &Connection, id: Uuid) -> Result<Option<StoredConnectionNode>> {
    let sql = format!("SELECT {SELECT_COLUMNS} FROM Nodes WHERE Id = ?1 COLLATE NOCASE;");
    let mut stmt = conn.prepare(&sql)?;
    let id_text = format_guid_d(id);
    Ok(stmt
        .query_row(params![id_text], map_stored_node)
        .optional()?)
}

fn require_folder_on(conn: &Connection, folder_id: Uuid) -> Result<StoredConnectionNode> {
    let stored = get_by_id_on(conn, folder_id)?.ok_or(StorageError::NotFound(folder_id))?;
    if stored.node.kind != NodeKind::Folder {
        return Err(StorageError::InvalidArgument(
            "expected a folder node".into(),
        ));
    }
    Ok(stored)
}

fn next_sort_order_on(conn: &Connection, parent_id: Option<Uuid>) -> Result<i32> {
    let max: Option<i32> = match parent_id {
        None => conn.query_row(
            "SELECT MAX(SortOrder) FROM Nodes WHERE ParentId IS NULL;",
            [],
            |r| r.get(0),
        )?,
        Some(pid) => conn.query_row(
            "SELECT MAX(SortOrder) FROM Nodes WHERE ParentId = ?1 COLLATE NOCASE;",
            params![format_guid_d(pid)],
            |r| r.get(0),
        )?,
    };
    // Saturate rather than wrap if a hostile/migrated row already sits at i32::MAX.
    Ok(max.map(|m| m.saturating_add(1)).unwrap_or(0))
}

fn require_nonblank_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidArgument(
            "folder name must be non-blank".into(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn insert_on(conn: &Connection, node: &ConnectionNode, now: DateTime<Utc>) -> Result<()> {
    let binds = NodeSqlBinds::from_node(node, now, now);
    let sql = format!("INSERT INTO Nodes ({SELECT_COLUMNS}) VALUES ({INSERT_PLACEHOLDERS});");
    // Inline `params!` -- returning `params!` from a helper cannot borrow the temporary pack.
    conn.execute(
        &sql,
        params![
            binds.id,
            binds.parent_id,
            binds.name,
            binds.kind,
            binds.sort_order,
            binds.protocol,
            binds.host,
            binds.port,
            binds.username,
            binds.credential_id,
            binds.credential_mode,
            binds.use_inline_password,
            binds.rdp_domain,
            binds.rdp_screen_size,
            binds.rdp_full_screen,
            binds.rdp_color_depth,
            binds.rdp_use_all_monitors,
            binds.rdp_audio_mode,
            binds.rdp_audio_capture_mode,
            binds.rdp_keyboard_hook_mode,
            binds.rdp_redirect_clipboard,
            binds.rdp_redirect_printers,
            binds.rdp_redirect_smart_cards,
            binds.rdp_redirect_ports,
            binds.rdp_redirect_devices,
            binds.rdp_redirect_drives,
            binds.rdp_connection_speed,
            binds.rdp_desktop_background,
            binds.rdp_font_smoothing,
            binds.rdp_desktop_composition,
            binds.rdp_window_drag,
            binds.rdp_menu_animation,
            binds.rdp_visual_styles,
            binds.rdp_bitmap_caching,
            binds.rdp_auto_reconnect,
            binds.rdp_server_authentication,
            binds.rdp_gateway_usage_method,
            binds.rdp_gateway_hostname,
            binds.rdp_gateway_credential_id,
            binds.rdp_gateway_bypass_local,
            binds.rdp_gateway_use_same_creds,
            binds.rdp_use_external_client,
            binds.ssh_key_file_name,
            binds.ssh_known_host_fingerprint,
            binds.ssh_auto_sudo,
            binds.serial_baud_rate,
            binds.serial_data_bits,
            binds.serial_stop_bits,
            binds.serial_parity,
            binds.serial_flow_control,
            binds.http_ignore_cert_errors,
            binds.tunnel_enabled,
            binds.tunnel_config_id,
            binds.created_at,
            binds.updated_at,
        ],
    )?;
    Ok(())
}

fn update_on(conn: &Connection, node: &ConnectionNode, now: DateTime<Utc>) -> Result<()> {
    // `from_node` also formats CreatedAt; UPDATE ignores it (Id + mutable cols + UpdatedAt only).
    let binds = NodeSqlBinds::from_node(node, now, now);
    let sql = format!("UPDATE Nodes SET {UPDATE_ASSIGNMENTS} WHERE Id = ?1 COLLATE NOCASE;");
    // UPDATE params: Id + all mutable fields ending with UpdatedAt (no CreatedAt).
    conn.execute(
        &sql,
        params![
            binds.id,
            binds.parent_id,
            binds.name,
            binds.kind,
            binds.sort_order,
            binds.protocol,
            binds.host,
            binds.port,
            binds.username,
            binds.credential_id,
            binds.credential_mode,
            binds.use_inline_password,
            binds.rdp_domain,
            binds.rdp_screen_size,
            binds.rdp_full_screen,
            binds.rdp_color_depth,
            binds.rdp_use_all_monitors,
            binds.rdp_audio_mode,
            binds.rdp_audio_capture_mode,
            binds.rdp_keyboard_hook_mode,
            binds.rdp_redirect_clipboard,
            binds.rdp_redirect_printers,
            binds.rdp_redirect_smart_cards,
            binds.rdp_redirect_ports,
            binds.rdp_redirect_devices,
            binds.rdp_redirect_drives,
            binds.rdp_connection_speed,
            binds.rdp_desktop_background,
            binds.rdp_font_smoothing,
            binds.rdp_desktop_composition,
            binds.rdp_window_drag,
            binds.rdp_menu_animation,
            binds.rdp_visual_styles,
            binds.rdp_bitmap_caching,
            binds.rdp_auto_reconnect,
            binds.rdp_server_authentication,
            binds.rdp_gateway_usage_method,
            binds.rdp_gateway_hostname,
            binds.rdp_gateway_credential_id,
            binds.rdp_gateway_bypass_local,
            binds.rdp_gateway_use_same_creds,
            binds.rdp_use_external_client,
            binds.ssh_key_file_name,
            binds.ssh_known_host_fingerprint,
            binds.ssh_auto_sudo,
            binds.serial_baud_rate,
            binds.serial_data_bits,
            binds.serial_stop_bits,
            binds.serial_parity,
            binds.serial_flow_control,
            binds.http_ignore_cert_errors,
            binds.tunnel_enabled,
            binds.tunnel_config_id,
            binds.updated_at,
        ],
    )?;
    Ok(())
}

const INSERT_PLACEHOLDERS: &str = "\
?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, \
?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, \
?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55";

/// Owned SQL bind values for a `Nodes` row (GUID D + timestamp O + int enums).
struct NodeSqlBinds {
    id: String,
    parent_id: Option<String>,
    name: String,
    kind: i32,
    sort_order: i32,
    protocol: Option<i32>,
    host: Option<String>,
    port: Option<i32>,
    username: Option<String>,
    credential_id: Option<String>,
    credential_mode: Option<i32>,
    use_inline_password: Option<i32>,
    rdp_domain: Option<String>,
    rdp_screen_size: Option<String>,
    rdp_full_screen: Option<i32>,
    rdp_color_depth: Option<i32>,
    rdp_use_all_monitors: Option<i32>,
    rdp_audio_mode: Option<i32>,
    rdp_audio_capture_mode: Option<i32>,
    rdp_keyboard_hook_mode: Option<i32>,
    rdp_redirect_clipboard: Option<i32>,
    rdp_redirect_printers: Option<i32>,
    rdp_redirect_smart_cards: Option<i32>,
    rdp_redirect_ports: Option<i32>,
    rdp_redirect_devices: Option<i32>,
    rdp_redirect_drives: Option<String>,
    rdp_connection_speed: Option<i32>,
    rdp_desktop_background: Option<i32>,
    rdp_font_smoothing: Option<i32>,
    rdp_desktop_composition: Option<i32>,
    rdp_window_drag: Option<i32>,
    rdp_menu_animation: Option<i32>,
    rdp_visual_styles: Option<i32>,
    rdp_bitmap_caching: Option<i32>,
    rdp_auto_reconnect: Option<i32>,
    rdp_server_authentication: Option<i32>,
    rdp_gateway_usage_method: Option<i32>,
    rdp_gateway_hostname: Option<String>,
    rdp_gateway_credential_id: Option<String>,
    rdp_gateway_bypass_local: Option<i32>,
    rdp_gateway_use_same_creds: Option<i32>,
    rdp_use_external_client: Option<i32>,
    ssh_key_file_name: Option<String>,
    ssh_known_host_fingerprint: Option<String>,
    ssh_auto_sudo: Option<i32>,
    serial_baud_rate: Option<i32>,
    serial_data_bits: Option<i32>,
    serial_stop_bits: Option<i32>,
    serial_parity: Option<i32>,
    serial_flow_control: Option<i32>,
    http_ignore_cert_errors: Option<i32>,
    tunnel_enabled: Option<i32>,
    tunnel_config_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl NodeSqlBinds {
    fn from_node(node: &ConnectionNode, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        Self {
            id: format_guid_d(node.id),
            parent_id: node.parent_id.map(format_guid_d),
            name: node.name.clone(),
            kind: node.kind as i32,
            sort_order: node.sort_order,
            protocol: node.protocol.map(|p| p as i32),
            host: node.host.clone(),
            port: node.port,
            username: node.username.clone(),
            credential_id: node.credential_id.map(format_guid_d),
            credential_mode: node.credential_mode.map(|m| m as i32),
            use_inline_password: bool_sql(node.use_inline_password),
            rdp_domain: node.rdp_domain.clone(),
            rdp_screen_size: node.rdp_screen_size.clone(),
            rdp_full_screen: bool_sql(node.rdp_full_screen),
            rdp_color_depth: node.rdp_color_depth,
            rdp_use_all_monitors: bool_sql(node.rdp_use_all_monitors),
            rdp_audio_mode: node.rdp_audio_mode,
            rdp_audio_capture_mode: node.rdp_audio_capture_mode,
            rdp_keyboard_hook_mode: node.rdp_keyboard_hook_mode,
            rdp_redirect_clipboard: bool_sql(node.rdp_redirect_clipboard),
            rdp_redirect_printers: bool_sql(node.rdp_redirect_printers),
            rdp_redirect_smart_cards: bool_sql(node.rdp_redirect_smart_cards),
            rdp_redirect_ports: bool_sql(node.rdp_redirect_ports),
            rdp_redirect_devices: bool_sql(node.rdp_redirect_devices),
            rdp_redirect_drives: node.rdp_redirect_drives.clone(),
            rdp_connection_speed: node.rdp_connection_speed,
            rdp_desktop_background: bool_sql(node.rdp_desktop_background),
            rdp_font_smoothing: bool_sql(node.rdp_font_smoothing),
            rdp_desktop_composition: bool_sql(node.rdp_desktop_composition),
            rdp_window_drag: bool_sql(node.rdp_window_drag),
            rdp_menu_animation: bool_sql(node.rdp_menu_animation),
            rdp_visual_styles: bool_sql(node.rdp_visual_styles),
            rdp_bitmap_caching: bool_sql(node.rdp_bitmap_caching),
            rdp_auto_reconnect: bool_sql(node.rdp_auto_reconnect),
            rdp_server_authentication: node.rdp_server_authentication,
            rdp_gateway_usage_method: node.rdp_gateway_usage_method,
            rdp_gateway_hostname: node.rdp_gateway_hostname.clone(),
            rdp_gateway_credential_id: node.rdp_gateway_credential_id.map(format_guid_d),
            rdp_gateway_bypass_local: bool_sql(node.rdp_gateway_bypass_local),
            rdp_gateway_use_same_creds: bool_sql(node.rdp_gateway_use_same_creds),
            rdp_use_external_client: bool_sql(node.rdp_use_external_client),
            ssh_key_file_name: node.ssh_key_file_name.clone(),
            ssh_known_host_fingerprint: node.ssh_known_host_fingerprint.clone(),
            ssh_auto_sudo: bool_sql(node.ssh_auto_sudo),
            serial_baud_rate: node.serial_baud_rate,
            serial_data_bits: node.serial_data_bits,
            serial_stop_bits: node.serial_stop_bits.map(|v| v as i32),
            serial_parity: node.serial_parity.map(|v| v as i32),
            serial_flow_control: node.serial_flow_control.map(|v| v as i32),
            http_ignore_cert_errors: bool_sql(node.http_ignore_cert_errors),
            tunnel_enabled: bool_sql(node.tunnel_enabled),
            tunnel_config_id: node.tunnel_config_id.map(format_guid_d),
            created_at: format_timestamp_o(created_at),
            updated_at: format_timestamp_o(updated_at),
        }
    }
}

fn bool_sql(v: Option<bool>) -> Option<i32> {
    v.map(|b| if b { 1 } else { 0 })
}

fn map_stored_node(row: &Row<'_>) -> rusqlite::Result<StoredConnectionNode> {
    let kind_i: i32 = row.get("Kind")?;
    let kind = match kind_i {
        0 => NodeKind::Folder,
        1 => NodeKind::Connection,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                format!("unknown NodeKind {other}").into(),
            ));
        }
    };
    let node = ConnectionNode {
        id: parse_guid_col(row, "Id")?,
        parent_id: opt_guid_col(row, "ParentId")?,
        name: row.get("Name")?,
        kind,
        sort_order: row.get("SortOrder")?,
        protocol: opt_protocol(row.get("Protocol")?)?,
        host: row.get("Host")?,
        port: row.get("Port")?,
        username: row.get("Username")?,
        credential_id: opt_guid_col(row, "CredentialId")?,
        credential_mode: opt_credential_mode(row.get("CredentialMode")?)?,
        use_inline_password: opt_bool(row.get("UseInlinePassword")?),
        rdp_domain: row.get("RdpDomain")?,
        rdp_screen_size: row.get("RdpScreenSize")?,
        rdp_full_screen: opt_bool(row.get("RdpFullScreen")?),
        rdp_color_depth: row.get("RdpColorDepth")?,
        rdp_use_all_monitors: opt_bool(row.get("RdpUseAllMonitors")?),
        rdp_audio_mode: row.get("RdpAudioMode")?,
        rdp_audio_capture_mode: row.get("RdpAudioCaptureMode")?,
        rdp_keyboard_hook_mode: row.get("RdpKeyboardHookMode")?,
        rdp_redirect_clipboard: opt_bool(row.get("RdpRedirectClipboard")?),
        rdp_redirect_printers: opt_bool(row.get("RdpRedirectPrinters")?),
        rdp_redirect_smart_cards: opt_bool(row.get("RdpRedirectSmartCards")?),
        rdp_redirect_ports: opt_bool(row.get("RdpRedirectPorts")?),
        rdp_redirect_devices: opt_bool(row.get("RdpRedirectDevices")?),
        rdp_redirect_drives: row.get("RdpRedirectDrives")?,
        rdp_connection_speed: row.get("RdpConnectionSpeed")?,
        rdp_desktop_background: opt_bool(row.get("RdpDesktopBackground")?),
        rdp_font_smoothing: opt_bool(row.get("RdpFontSmoothing")?),
        rdp_desktop_composition: opt_bool(row.get("RdpDesktopComposition")?),
        rdp_window_drag: opt_bool(row.get("RdpWindowDrag")?),
        rdp_menu_animation: opt_bool(row.get("RdpMenuAnimation")?),
        rdp_visual_styles: opt_bool(row.get("RdpVisualStyles")?),
        rdp_bitmap_caching: opt_bool(row.get("RdpBitmapCaching")?),
        rdp_auto_reconnect: opt_bool(row.get("RdpAutoReconnect")?),
        rdp_server_authentication: row.get("RdpServerAuthentication")?,
        rdp_gateway_usage_method: row.get("RdpGatewayUsageMethod")?,
        rdp_gateway_hostname: row.get("RdpGatewayHostname")?,
        rdp_gateway_credential_id: opt_guid_col(row, "RdpGatewayCredentialId")?,
        rdp_gateway_bypass_local: opt_bool(row.get("RdpGatewayBypassLocal")?),
        rdp_gateway_use_same_creds: opt_bool(row.get("RdpGatewayUseSameCreds")?),
        rdp_use_external_client: opt_bool(row.get("RdpUseExternalClient")?),
        ssh_key_file_name: row.get("SshKeyFileName")?,
        ssh_known_host_fingerprint: row.get("SshKnownHostFingerprint")?,
        ssh_auto_sudo: opt_bool(row.get("SshAutoSudo")?),
        serial_baud_rate: row.get("SerialBaudRate")?,
        serial_data_bits: row.get("SerialDataBits")?,
        serial_stop_bits: opt_stop_bits(row.get("SerialStopBits")?)?,
        serial_parity: opt_parity(row.get("SerialParity")?)?,
        serial_flow_control: opt_flow(row.get("SerialFlowControl")?)?,
        http_ignore_cert_errors: opt_bool(row.get("HttpIgnoreCertErrors")?),
        tunnel_enabled: opt_bool(row.get("TunnelEnabled")?),
        tunnel_config_id: opt_guid_col(row, "TunnelConfigId")?,
    };
    Ok(StoredConnectionNode {
        node,
        created_at: parse_ts_col(row, "CreatedAt")?,
        updated_at: parse_ts_col(row, "UpdatedAt")?,
    })
}

fn opt_bool(v: Option<i64>) -> Option<bool> {
    v.map(|n| n != 0)
}

fn conversion_err(msg: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, msg.into())
}

fn opt_protocol(v: Option<i32>) -> rusqlite::Result<Option<ProtocolType>> {
    match v {
        None => Ok(None),
        Some(0) => Ok(Some(ProtocolType::Ssh)),
        Some(1) => Ok(Some(ProtocolType::Rdp)),
        Some(3) => Ok(Some(ProtocolType::Http)),
        Some(4) => Ok(Some(ProtocolType::Https)),
        Some(5) => Ok(Some(ProtocolType::Serial)),
        Some(6) => Ok(Some(ProtocolType::Vnc)),
        Some(n) => Err(conversion_err(format!("unknown ProtocolType {n}"))),
    }
}

fn opt_credential_mode(v: Option<i32>) -> rusqlite::Result<Option<CredentialBindingMode>> {
    match v {
        None => Ok(None),
        Some(0) => Ok(Some(CredentialBindingMode::Inherit)),
        Some(1) => Ok(Some(CredentialBindingMode::None)),
        Some(2) => Ok(Some(CredentialBindingMode::Saved)),
        Some(n) => Err(conversion_err(format!("unknown CredentialBindingMode {n}"))),
    }
}

fn opt_stop_bits(v: Option<i32>) -> rusqlite::Result<Option<SerialStopBitsMode>> {
    match v {
        None => Ok(None),
        Some(1) => Ok(Some(SerialStopBitsMode::One)),
        Some(2) => Ok(Some(SerialStopBitsMode::Two)),
        Some(3) => Ok(Some(SerialStopBitsMode::OnePointFive)),
        Some(n) => Err(conversion_err(format!("unknown SerialStopBitsMode {n}"))),
    }
}

fn opt_parity(v: Option<i32>) -> rusqlite::Result<Option<SerialParityMode>> {
    match v {
        None => Ok(None),
        Some(0) => Ok(Some(SerialParityMode::None)),
        Some(1) => Ok(Some(SerialParityMode::Odd)),
        Some(2) => Ok(Some(SerialParityMode::Even)),
        Some(3) => Ok(Some(SerialParityMode::Mark)),
        Some(4) => Ok(Some(SerialParityMode::Space)),
        Some(n) => Err(conversion_err(format!("unknown SerialParityMode {n}"))),
    }
}

fn opt_flow(v: Option<i32>) -> rusqlite::Result<Option<SerialFlowControlMode>> {
    match v {
        None => Ok(None),
        Some(0) => Ok(Some(SerialFlowControlMode::None)),
        Some(1) => Ok(Some(SerialFlowControlMode::XonXoff)),
        Some(2) => Ok(Some(SerialFlowControlMode::RtsCts)),
        Some(3) => Ok(Some(SerialFlowControlMode::DsrDtr)),
        Some(n) => Err(conversion_err(format!("unknown SerialFlowControlMode {n}"))),
    }
}

fn parse_guid_col(row: &Row<'_>, col: &str) -> rusqlite::Result<Uuid> {
    let s: String = row.get(col)?;
    parse_guid_d(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn opt_guid_col(row: &Row<'_>, col: &str) -> rusqlite::Result<Option<Uuid>> {
    let s: Option<String> = row.get(col)?;
    match s {
        None => Ok(None),
        Some(value) => parse_guid_d(&value).map(Some).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        }),
    }
}

fn parse_ts_col(row: &Row<'_>, col: &str) -> rusqlite::Result<DateTime<Utc>> {
    let s: String = row.get(col)?;
    parse_timestamp_o(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}
