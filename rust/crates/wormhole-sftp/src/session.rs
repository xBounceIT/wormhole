//! Serialized SFTP session — one op at a time per session.
//!
//! Mirrors `FileTransferOrchestrator.RunSerializedAsync` / `SemaphoreSlim(1,1)`:
//! every public method acquires the gate, runs the backend call to completion,
//! then releases. **Caller cancellation does not release the gate while a worker
//! still holds the backend** (parity with the C# anti-pattern fix in
//! `SftpSession.RunAsync`): work is driven on a spawned task that owns the
//! mutex until the backend future finishes.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{oneshot, Mutex};

use crate::entry::SftpEntry;
use crate::ops::SftpOps;
use crate::SftpError;

struct Inner<B: SftpOps> {
    backend: B,
    /// Mutex = non-reentrant single-flight (same shape as SemaphoreSlim(1,1)).
    gate: Mutex<()>,
    closed: AtomicBool,
    /// Test/observability: how many ops completed under the gate.
    ops_completed: AtomicUsize,
    /// Test/observability: how many times the gate was acquired for real work.
    gate_acquisitions: AtomicUsize,
}

/// Wraps any [`SftpOps`] backend so concurrent callers cannot interleave requests.
pub struct SerializedSftpSession<B: SftpOps> {
    inner: Arc<Inner<B>>,
}

impl<B: SftpOps + 'static> SerializedSftpSession<B> {
    pub fn new(backend: B) -> Self {
        Self {
            inner: Arc::new(Inner {
                backend,
                gate: Mutex::new(()),
                closed: AtomicBool::new(false),
                ops_completed: AtomicUsize::new(0),
                gate_acquisitions: AtomicUsize::new(0),
            }),
        }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    pub fn backend(&self) -> &B {
        &self.inner.backend
    }

    pub fn working_directory(&self) -> &str {
        self.inner.backend.working_directory()
    }

    pub fn host_fingerprint(&self) -> Option<&str> {
        self.inner.backend.host_fingerprint()
    }

    pub fn is_connected(&self) -> bool {
        !self.inner.closed.load(Ordering::SeqCst) && self.inner.backend.is_connected()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn ops_completed(&self) -> usize {
        self.inner.ops_completed.load(Ordering::SeqCst)
    }

    pub fn gate_acquisitions(&self) -> usize {
        self.inner.gate_acquisitions.load(Ordering::SeqCst)
    }

    /// Drive `fut` under the serialization gate on a worker task.
    ///
    /// If the caller cancels while waiting for the result, the worker still
    /// finishes the backend op (and only then releases the gate). If the caller
    /// cancels *before* the worker acquires the gate, the worker skips the op.
    async fn drive<R, Fut>(&self, fut: Fut) -> Result<R, SftpError>
    where
        Fut: Future<Output = Result<R, SftpError>> + Send + 'static,
        R: Send + 'static,
    {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(SftpError::Closed);
        }

        let inner = Arc::clone(&self.inner);
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let _guard = inner.gate.lock().await;
            if inner.closed.load(Ordering::SeqCst) {
                let _ = tx.send(Err(SftpError::Closed));
                return;
            }
            // Cancelled while queued for the gate — do not start backend work.
            if tx.is_closed() {
                return;
            }
            inner.gate_acquisitions.fetch_add(1, Ordering::SeqCst);
            let result = fut.await;
            inner.ops_completed.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(result);
        });

        match rx.await {
            Ok(r) => r,
            Err(_) => Err(SftpError::Operation(
                "SFTP worker terminated unexpectedly".into(),
            )),
        }
    }

    /// Run an arbitrary async closure under the serialization gate.
    ///
    /// Prefer the typed methods below for normal ops. This exists for pane-level
    /// multi-step work that must stay single-flight (C# `RunSerializedAsync`).
    ///
    /// The closure must be `Send + 'static` so the worker can outlive caller cancel.
    pub async fn run_serialized<R, F, Fut>(&self, f: F) -> Result<R, SftpError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<R, SftpError>> + Send + 'static,
        R: Send + 'static,
    {
        self.drive(f()).await
    }

    pub async fn list_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
        let path = path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.list_directory(&path).await })
            .await
    }

    pub async fn get_attributes(&self, path: &str) -> Result<Option<SftpEntry>, SftpError> {
        let path = path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.get_attributes(&path).await })
            .await
    }

    pub async fn exists(&self, path: &str) -> Result<bool, SftpError> {
        let path = path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.exists(&path).await })
            .await
    }

    pub async fn upload(&self, remote_path: &str, data: &[u8]) -> Result<(), SftpError> {
        let remote_path = remote_path.to_owned();
        let data = data.to_vec();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.upload(&remote_path, &data).await })
            .await
    }

    pub async fn download(&self, remote_path: &str) -> Result<Vec<u8>, SftpError> {
        let remote_path = remote_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.download(&remote_path).await })
            .await
    }

    pub async fn create_directory(&self, remote_path: &str) -> Result<(), SftpError> {
        let remote_path = remote_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.create_directory(&remote_path).await })
            .await
    }

    pub async fn create_empty_file(&self, remote_path: &str) -> Result<(), SftpError> {
        let remote_path = remote_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.create_empty_file(&remote_path).await })
            .await
    }

    pub async fn delete_file(&self, remote_path: &str) -> Result<(), SftpError> {
        let remote_path = remote_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.delete_file(&remote_path).await })
            .await
    }

    pub async fn delete_directory(
        &self,
        remote_path: &str,
        recursive: bool,
    ) -> Result<(), SftpError> {
        let remote_path = remote_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move {
            inner
                .backend
                .delete_directory(&remote_path, recursive)
                .await
        })
        .await
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), SftpError> {
        let old_path = old_path.to_owned();
        let new_path = new_path.to_owned();
        let inner = Arc::clone(&self.inner);
        self.drive(async move { inner.backend.rename(&old_path, &new_path).await })
            .await
    }

    /// Mark closed. In-flight ops finish; new acquisitions fail with [`SftpError::Closed`].
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}
