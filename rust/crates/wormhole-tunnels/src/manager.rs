use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use tracing::info;
use uuid::Uuid;

use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelLease, TunnelProvider,
    TunnelState,
};

type EstablishShared =
    Shared<BoxFuture<'static, Result<Arc<dyn TunnelInstance>, EstablishSharedError>>>;

/// Shared-future error. Never holds secret blobs — only opaque establish messages / typed codes.
#[derive(Debug, Clone)]
enum EstablishSharedError {
    Cancelled,
    /// Opaque provider establish failure (must not contain secret material).
    Failed(String),
    NotImplemented {
        kind: TunnelKind,
        sidecar: &'static str,
    },
    BinaryNotFound {
        binary: String,
        searched: Vec<String>,
    },
    ConfigNotFound {
        id: Uuid,
    },
    SecretMissing {
        id: Uuid,
    },
    WrongKind {
        expected: TunnelKind,
        actual: TunnelKind,
    },
}

impl From<TunnelError> for EstablishSharedError {
    fn from(value: TunnelError) -> Self {
        match value {
            TunnelError::Cancelled => Self::Cancelled,
            // Preserve message without Display double-wrap (`tunnel establishment failed: …`).
            TunnelError::Establish(msg) => Self::Failed(msg),
            TunnelError::NotImplemented { kind, sidecar } => Self::NotImplemented { kind, sidecar },
            TunnelError::BinaryNotFound { binary, searched } => {
                Self::BinaryNotFound { binary, searched }
            }
            TunnelError::ConfigNotFound { id } => Self::ConfigNotFound { id },
            TunnelError::SecretMissing { id } => Self::SecretMissing { id },
            TunnelError::WrongKind { expected, actual } => Self::WrongKind { expected, actual },
            other => Self::Failed(other.to_string()),
        }
    }
}

impl From<EstablishSharedError> for TunnelError {
    fn from(value: EstablishSharedError) -> Self {
        match value {
            EstablishSharedError::Cancelled => TunnelError::Cancelled,
            EstablishSharedError::Failed(msg) => TunnelError::Establish(msg),
            EstablishSharedError::NotImplemented { kind, sidecar } => {
                TunnelError::NotImplemented { kind, sidecar }
            }
            EstablishSharedError::BinaryNotFound { binary, searched } => {
                TunnelError::BinaryNotFound { binary, searched }
            }
            EstablishSharedError::ConfigNotFound { id } => TunnelError::ConfigNotFound { id },
            EstablishSharedError::SecretMissing { id } => TunnelError::SecretMissing { id },
            EstablishSharedError::WrongKind { expected, actual } => {
                TunnelError::WrongKind { expected, actual }
            }
        }
    }
}

struct SharedEntry {
    config_id: Uuid,
    config_updated_at: std::time::SystemTime,
    ref_count: usize,
    establish: EstablishShared,
    instance: Option<Arc<dyn TunnelInstance>>,
    cancelled: Arc<AtomicBool>,
}

type PoolMap = HashMap<Uuid, Arc<Mutex<SharedEntry>>>;

/// Holds a pool ref for one `establish` caller. Dropping (cancel) releases the ref — matching
/// C# `ReleaseAsync` on `WaitAsync` cancellation — so mid-establish drops cannot leak the pool.
struct EstablishRefGuard {
    pool: Arc<Mutex<PoolMap>>,
    entry: Option<Arc<Mutex<SharedEntry>>>,
}

impl EstablishRefGuard {
    fn new(pool: Arc<Mutex<PoolMap>>, entry: Arc<Mutex<SharedEntry>>) -> Self {
        Self {
            pool,
            entry: Some(entry),
        }
    }

    fn disarm(mut self) -> Arc<Mutex<SharedEntry>> {
        self.entry.take().expect("establish ref still armed")
    }
}

impl Drop for EstablishRefGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            release_entry(&self.pool, &entry);
        }
    }
}

/// Ref-counted, coalesce-aware tunnel pool — thin lease glue for C# `TunnelManager`.
///
/// Concurrent `establish` for the same `TunnelConfigId` shares one provider future
/// (one OTP / one sidecar spawn). Last lease release closes the instance.
/// `UpdatedAt` mismatch or instance `Failed`/`Closed` evicts and establishes fresh
/// (outstanding leases drain the old entry). No live VPN — providers may be Fakes.
pub struct TunnelManager {
    providers: HashMap<TunnelKind, Arc<dyn TunnelProvider>>,
    pool: Arc<Mutex<PoolMap>>,
    /// How many times a provider `establish` was started (tests / diagnostics).
    establish_starts: AtomicUsize,
}

impl std::fmt::Debug for TunnelManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pool = lock_pool(&self.pool);
        let kinds: Vec<TunnelKind> = self.providers.keys().copied().collect();
        f.debug_struct("TunnelManager")
            .field("provider_kinds", &kinds)
            .field("pool_size", &pool.len())
            .field(
                "establish_starts",
                &self.establish_starts.load(Ordering::SeqCst),
            )
            .finish()
    }
}

impl TunnelManager {
    pub fn new(providers: impl IntoIterator<Item = Arc<dyn TunnelProvider>>) -> Result<Self, TunnelError> {
        let mut by_kind = HashMap::new();
        for provider in providers {
            let kind = provider.kind();
            if by_kind.contains_key(&kind) {
                return Err(TunnelError::Establish(format!(
                    "multiple TunnelProvider registrations for {kind:?}"
                )));
            }
            by_kind.insert(kind, provider);
        }
        Ok(Self {
            providers: by_kind,
            pool: Arc::new(Mutex::new(HashMap::new())),
            establish_starts: AtomicUsize::new(0),
        })
    }

    pub fn establish_start_count(&self) -> usize {
        self.establish_starts.load(Ordering::SeqCst)
    }

    /// Pool depth for a config (0 if absent). Test helper.
    pub fn pool_ref_count(&self, config_id: Uuid) -> usize {
        let pool = lock_pool(&self.pool);
        pool.get(&config_id)
            .map(|e| lock_entry(e).ref_count)
            .unwrap_or(0)
    }

    /// Returns a lease over the shared tunnel for `config`, establishing if needed.
    ///
    /// Concurrent callers for the same `config.id` share one provider establishment.
    /// Dropping the returned future (or cancelling its task) releases this caller's pool ref;
    /// the shared establishment aborts ownership only when the last waiter is gone.
    pub async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> Result<TunnelLease, TunnelError> {
        let provider = self
            .providers
            .get(&config.kind)
            .cloned()
            .ok_or(TunnelError::NoProvider(config.kind))?;

        let entry = self.acquire_entry(&config, provider, secret_blob)?;
        let guard = EstablishRefGuard::new(Arc::clone(&self.pool), Arc::clone(&entry));
        let establish = {
            let guard_entry = lock_entry(&entry);
            guard_entry.establish.clone()
        };

        match establish.await {
            Ok(instance) => {
                let entry = guard.disarm();
                Ok(make_lease(Arc::clone(&self.pool), entry, instance))
            }
            Err(e) => {
                // Guard Drop releases this caller's ref (and cancels if last + still establishing).
                drop(guard);
                Err(e.into())
            }
        }
    }

    fn acquire_entry(
        &self,
        config: &TunnelConfigSnapshot,
        provider: Arc<dyn TunnelProvider>,
        secret_blob: Vec<u8>,
    ) -> Result<Arc<Mutex<SharedEntry>>, TunnelError> {
        let mut pool = lock_pool(&self.pool);

        if let Some(existing) = pool.get(&config.id).cloned() {
            let mut guard = lock_entry(&existing);
            // Refuse zero-ref / cancelled entries (defense in depth — release holds the pool
            // lock across the zero transition so this should not appear, matching C# single gate).
            if !entry_unusable_for_reuse(&guard, config) {
                guard.ref_count += 1;
                drop(guard);
                return Ok(existing);
            }
            drop(guard);
            // Evict so a fresh entry is built below; outstanding leases keep draining the old
            // instance (ptr_eq release still closes it when their ref-count hits zero).
            pool.remove(&config.id);
        }

        self.establish_starts.fetch_add(1, Ordering::SeqCst);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_flag = Arc::clone(&cancelled);
        let config_for_task = config.clone();
        let config_id = config.id;
        let pool_for_task = Arc::clone(&self.pool);

        let entry = Arc::new_cyclic(|weak: &Weak<Mutex<SharedEntry>>| {
            let weak = weak.clone();
            let establish: EstablishShared = async move {
                if cancel_flag.load(Ordering::SeqCst) {
                    return Err(EstablishSharedError::Cancelled);
                }
                let instance = match provider.establish(&config_for_task, &secret_blob).await {
                    Ok(instance) => instance,
                    Err(e) => {
                        if let Some(entry) = weak.upgrade() {
                            evict_if_same(&pool_for_task, config_id, &entry);
                        }
                        return Err(EstablishSharedError::from(e));
                    }
                };

                let Some(entry) = weak.upgrade() else {
                    instance.close().await;
                    return Err(EstablishSharedError::Cancelled);
                };

                let orphaned = {
                    let mut guard = lock_entry(&entry);
                    let orphaned =
                        guard.ref_count == 0 || guard.cancelled.load(Ordering::SeqCst);
                    if !orphaned {
                        guard.instance = Some(Arc::clone(&instance));
                    }
                    orphaned
                };
                if orphaned {
                    // Every waiter cancelled while the provider was establishing. Nobody owns
                    // the result — close it (parity with C# EstablishSharedCoreAsync).
                    instance.close().await;
                    evict_if_same(&pool_for_task, config_id, &entry);
                    return Err(EstablishSharedError::Cancelled);
                }
                Ok(instance)
            }
            .boxed()
            .shared();

            // Observe so failures aren't unobserved if every waiter cancels.
            tokio::spawn({
                let establish = establish.clone();
                async move {
                    let _ = establish.await;
                }
            });

            Mutex::new(SharedEntry {
                config_id,
                config_updated_at: config.updated_at,
                ref_count: 1,
                establish,
                instance: None,
                cancelled,
            })
        });

        pool.insert(config.id, Arc::clone(&entry));
        Ok(entry)
    }
}

fn make_lease(
    pool: Arc<Mutex<PoolMap>>,
    entry: Arc<Mutex<SharedEntry>>,
    instance: Arc<dyn TunnelInstance>,
) -> TunnelLease {
    TunnelLease {
        instance,
        on_release: Some(Box::new(move || {
            release_entry(&pool, &entry);
        })),
    }
}

fn evict_if_same(pool: &Arc<Mutex<PoolMap>>, config_id: Uuid, entry: &Arc<Mutex<SharedEntry>>) {
    let mut pool = lock_pool(pool);
    if let Some(current) = pool.get(&config_id)
        && Arc::ptr_eq(current, entry)
    {
        pool.remove(&config_id);
    }
}

fn release_entry(pool: &Arc<Mutex<PoolMap>>, entry: &Arc<Mutex<SharedEntry>>) {
    // Hold pool then entry (same order as acquire_entry) so a concurrent establish cannot
    // observe a zero-ref entry still mapped in the pool and resurrect a closing tunnel.
    let to_close = {
        let mut pool_guard = lock_pool(pool);
        let mut guard = lock_entry(entry);
        if guard.ref_count == 0 {
            return;
        }
        guard.ref_count -= 1;
        if guard.ref_count > 0 {
            return;
        }
        let config_id = guard.config_id;
        let instance = guard.instance.take();
        if instance.is_none() {
            guard.cancelled.store(true, Ordering::SeqCst);
        }
        if let Some(current) = pool_guard.get(&config_id)
            && Arc::ptr_eq(current, entry)
        {
            pool_guard.remove(&config_id);
        }
        (config_id, instance)
    };

    let (config_id, instance) = to_close;
    if let Some(instance) = instance {
        info!(%config_id, "closing shared tunnel — last lease released");
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                instance.close().await;
            });
        } else {
            // No runtime (sync Drop outside tokio): best-effort fire-and-forget via block_on is
            // unsafe here; mark closed synchronously if the stub supports it.
            warn_no_runtime_close();
        }
    }
}

fn lock_pool(pool: &Mutex<PoolMap>) -> std::sync::MutexGuard<'_, PoolMap> {
    pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_entry(entry: &Mutex<SharedEntry>) -> std::sync::MutexGuard<'_, SharedEntry> {
    entry.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn warn_no_runtime_close() {
    tracing::warn!("tunnel lease released with no tokio runtime; async close skipped");
}

fn is_unusable(
    entry_updated_at: std::time::SystemTime,
    config: &TunnelConfigSnapshot,
    state: Option<TunnelState>,
) -> bool {
    let stale = entry_updated_at != config.updated_at;
    let dead = matches!(state, Some(TunnelState::Failed | TunnelState::Closed));
    stale || dead
}

fn entry_unusable_for_reuse(entry: &SharedEntry, config: &TunnelConfigSnapshot) -> bool {
    entry.ref_count == 0
        || entry.cancelled.load(Ordering::SeqCst)
        || is_unusable(
            entry.config_updated_at,
            config,
            entry.instance.as_ref().map(|i| i.state()),
        )
}
