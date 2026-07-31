//! Transfer queue model — mirrors `TransferRequest` / orchestrator enqueue surface.
//!
//! This is the queue *shape* and single-flight execution helper. Full flatten /
//! conflict-prompt UI wiring stays with the host (parity with C# pane VMs).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::ops::SftpOps;
use crate::session::SerializedSftpSession;
use crate::SftpError;

/// Upload (local → remote) or download (remote → local).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

/// One source item in a batch (absolute POSIX remote path, or local path for upload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferItem {
    pub source_path: String,
    pub name: String,
    pub is_directory: bool,
}

/// A batch handed to the orchestrator (C# `TransferRequest`).
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub direction: TransferDirection,
    pub destination_directory: String,
    pub items: Vec<TransferItem>,
}

/// Observable transfer strip row state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct TransferJob {
    pub id: u64,
    pub direction: TransferDirection,
    pub source_path: String,
    pub destination_path: String,
    pub status: TransferStatus,
    pub error: Option<String>,
    pub bytes_transferred: u64,
}

/// In-memory transfer queue bound to a serialized SFTP session.
///
/// Enqueued file jobs run **one at a time** through the session gate (same invariant
/// as `FileTransferOrchestrator` wrapping each upload/download in `RunSerializedAsync`).
pub struct TransferQueue<B: SftpOps> {
    session: Arc<SerializedSftpSession<B>>,
    jobs: Mutex<Vec<TransferJob>>,
    next_id: AtomicU64,
}

impl<B: SftpOps + 'static> TransferQueue<B> {
    pub fn new(session: Arc<SerializedSftpSession<B>>) -> Self {
        Self {
            session,
            jobs: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn session(&self) -> &Arc<SerializedSftpSession<B>> {
        &self.session
    }

    pub fn jobs(&self) -> Vec<TransferJob> {
        self.jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Queue one file transfer and run it under the session serialization gate.
    ///
    /// Directory flatten / conflict prompts are host concerns; this helper assumes
    /// a single file path and absolute destination path.
    ///
    /// If the caller cancels this future mid-transfer, the session worker still
    /// finishes the backend op (gate safety), and the job row flips to
    /// [`TransferStatus::Cancelled`] unless a terminal status was already recorded.
    pub async fn enqueue_and_run_file(
        &self,
        direction: TransferDirection,
        source_path: impl Into<String>,
        destination_path: impl Into<String>,
        payload: Option<Vec<u8>>,
    ) -> Result<u64, SftpError> {
        let source_path = source_path.into();
        let destination_path = destination_path.into();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            jobs.push(TransferJob {
                id,
                direction,
                source_path: source_path.clone(),
                destination_path: destination_path.clone(),
                status: TransferStatus::Queued,
                error: None,
                bytes_transferred: 0,
            });
        }

        self.set_status(id, TransferStatus::Running, None, 0);
        // RAII: on cancel/drop before a terminal status is recorded, flip to Cancelled.
        let _guard = JobStatusGuard {
            queue: self,
            id,
        };

        let result = match direction {
            TransferDirection::Upload => {
                let data = payload.unwrap_or_default();
                let len = data.len() as u64;
                self.session
                    .upload(&destination_path, &data)
                    .await
                    .map(|()| len)
            }
            TransferDirection::Download => self
                .session
                .download(&source_path)
                .await
                .map(|bytes| {
                    let len = bytes.len() as u64;
                    // Host owns writing local bytes; we only exercise the remote op.
                    let _ = (destination_path, bytes);
                    len
                }),
        };

        match result {
            Ok(bytes) => {
                self.set_status(id, TransferStatus::Completed, None, bytes);
                Ok(id)
            }
            Err(e) => {
                // Transfer strip must never surface raw backend/credential-shaped text.
                self.set_status(id, TransferStatus::Failed, Some(e.public_message()), 0);
                Err(e)
            }
        }
    }

    fn set_status(
        &self,
        id: u64,
        status: TransferStatus,
        error: Option<String>,
        bytes: u64,
    ) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
            job.status = status;
            job.error = error;
            job.bytes_transferred = bytes;
        }
    }

    /// Flip Queued/Running → Cancelled. Terminal statuses (Completed/Failed/Skipped/
    /// Cancelled) are left untouched so a late Drop cannot clobber a recorded result.
    fn cancel_if_running(&self, id: u64) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(job) = jobs.iter_mut().find(|j| j.id == id)
            && matches!(
                job.status,
                TransferStatus::Queued | TransferStatus::Running
            )
        {
            job.status = TransferStatus::Cancelled;
        }
    }
}

/// On cancel/drop of `enqueue_and_run_file`, mark the job Cancelled if still active.
/// Terminal statuses are preserved by [`TransferQueue::cancel_if_running`].
struct JobStatusGuard<'a, B: SftpOps + 'static> {
    queue: &'a TransferQueue<B>,
    id: u64,
}

impl<B: SftpOps + 'static> Drop for JobStatusGuard<'_, B> {
    fn drop(&mut self) {
        self.queue.cancel_if_running(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeSftpBackend;

    #[tokio::test]
    async fn cancel_if_running_does_not_clobber_terminal_status() {
        let session = SerializedSftpSession::new(FakeSftpBackend::new()).into_arc();
        let queue = TransferQueue::new(session);

        let id = queue
            .enqueue_and_run_file(
                TransferDirection::Upload,
                "local/a.txt",
                "/home/user/a.txt",
                Some(b"x".to_vec()),
            )
            .await
            .unwrap();

        assert_eq!(queue.jobs()[0].status, TransferStatus::Completed);
        queue.cancel_if_running(id);
        assert_eq!(
            queue.jobs()[0].status,
            TransferStatus::Completed,
            "cancel_if_running must not overwrite Completed"
        );

        let err = queue
            .enqueue_and_run_file(
                TransferDirection::Download,
                "/home/user/missing.txt",
                "local/out.bin",
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SftpError::NotFound(_)));
        let failed_id = queue
            .jobs()
            .iter()
            .find(|j| j.status == TransferStatus::Failed)
            .unwrap()
            .id;
        queue.cancel_if_running(failed_id);
        assert_eq!(
            queue
                .jobs()
                .iter()
                .find(|j| j.id == failed_id)
                .unwrap()
                .status,
            TransferStatus::Failed
        );
    }
}
