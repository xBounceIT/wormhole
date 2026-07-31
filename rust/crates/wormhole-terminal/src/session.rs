use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::{Result, TerminalError};

/// Default capacity for [`channel_stub_pair`].
pub const CHANNEL_STUB_CAPACITY: usize = 256;

/// Terminal geometry (mirrors C# `TerminalSize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
}

impl TerminalSize {
    pub const DEFAULT: Self = Self {
        columns: 80,
        rows: 24,
    };

    pub fn new(columns: u32, rows: u32) -> Self {
        Self { columns, rows }
    }
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Events published by a [`TerminalSession`] read pump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    /// Bytes just read from the transport (caller must copy if retaining).
    Data(Bytes),
    /// Transport closed unexpectedly (distinct from local dispose).
    Closed,
}

/// Sender half of a session event channel stub.
pub type TerminalEventSender = mpsc::Sender<TerminalEvent>;
/// Receiver half of a session event channel stub.
pub type TerminalEventReceiver = mpsc::Receiver<TerminalEvent>;

/// Create a bounded event channel pair for session stubs / tests.
pub fn channel_stub_pair(capacity: usize) -> (TerminalEventSender, TerminalEventReceiver) {
    mpsc::channel(capacity)
}

/// PTY-like session trait mirroring C# `ITerminalSession`.
///
/// Implementations must not auto-start the read pump: callers subscribe to
/// [`TerminalEvent`]s first, then call [`start`](Self::start).
pub trait TerminalSession: Send {
    /// True once transport failure or disposal has begun.
    fn is_closing(&self) -> bool;

    /// Start the background read pump (idempotent).
    fn start(&self);

    /// Write bytes to the remote / serial peer.
    fn write<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

    /// Resize PTY geometry. Serial transports may no-op.
    fn resize(
        &self,
        columns: u32,
        rows: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;

    /// Request producer backpressure while the renderer catches up.
    fn pause_reading(&self);

    /// Resume a pump previously parked by [`pause_reading`](Self::pause_reading).
    fn resume_reading(&self);
}

/// In-memory [`TerminalSession`] for paste glue / unit tests (no PTY, no GPUI).
///
/// Records each [`write`](TerminalSession::write) payload. [`Debug`] shows write
/// counts and total UTF-8 length only — never paste / keystroke bodies.
#[derive(Clone, Default)]
pub struct FakeTerminalSession {
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    closing: Arc<AtomicBool>,
    /// After this many successful writes, auto-mark closing (`0` = disabled).
    /// Used to simulate mid-paste teardown between chunks.
    close_after_writes: Arc<AtomicUsize>,
    started: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl FakeTerminalSession {
    /// Empty session (open, not started).
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the session closing (subsequent writes / paste glue fail closed).
    pub fn mark_closing(&self) {
        self.closing.store(true, Ordering::Release);
    }

    /// After `n` successful writes, mark the session closing (`0` disables).
    ///
    /// Lets paste-glue tests fail closed mid-transaction: chunk `n` lands, then
    /// the next chunk sees [`is_closing`](TerminalSession::is_closing).
    pub fn close_after_n_writes(&self, n: usize) {
        self.close_after_writes.store(n, Ordering::Release);
    }

    /// Number of successful `write` calls.
    pub fn writes_count(&self) -> usize {
        self.writes.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Total bytes across all writes.
    pub fn total_bytes_written(&self) -> usize {
        self.writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|w| w.len())
            .sum()
    }

    /// Snapshot of write payloads (test helper — callers must not log bodies).
    pub fn writes(&self) -> Vec<Vec<u8>> {
        self.writes.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Synchronous write for non-async glue stubs (e.g. auto-sudo).
    ///
    /// Same fail-closed rules as [`TerminalSession::write`]. Prefer the async
    /// path when already on a runtime.
    pub fn write_bytes_sync(&self, data: &[u8]) -> Result<()> {
        if self.is_closing() {
            return Err(TerminalError::Closing);
        }
        let writes_so_far = {
            let mut guard = self.writes.lock().unwrap_or_else(|e| e.into_inner());
            guard.push(data.to_vec());
            guard.len()
        };
        let limit = self.close_after_writes.load(Ordering::Acquire);
        if limit > 0 && writes_so_far >= limit {
            self.closing.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Concatenate writes as UTF-8 (test helper).
    pub fn reassembled_utf8(&self) -> String {
        let mut out = String::new();
        for chunk in self.writes().iter() {
            out.push_str(std::str::from_utf8(chunk).unwrap_or("\u{FFFD}"));
        }
        out
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for FakeTerminalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTerminalSession")
            .field("writes_count", &self.writes_count())
            .field("utf8_len", &self.total_bytes_written())
            .field("closing", &self.closing.load(Ordering::Acquire))
            .field("started", &self.started.load(Ordering::Acquire))
            .field("paused", &self.paused.load(Ordering::Acquire))
            .finish()
    }
}

impl TerminalSession for FakeTerminalSession {
    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    fn start(&self) {
        self.started.store(true, Ordering::Release);
    }

    fn write<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { self.write_bytes_sync(data) })
    }

    fn resize(
        &self,
        _columns: u32,
        _rows: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            if self.is_closing() {
                return Err(TerminalError::Closing);
            }
            Ok(())
        })
    }

    fn pause_reading(&self) {
        self.paused.store(true, Ordering::Release);
    }

    fn resume_reading(&self) {
        self.paused.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_session_records_writes_and_redacts_debug() {
        let session = FakeTerminalSession::new();
        session.start();
        session.write(b"super-secret-keystrokes").await.unwrap();
        assert_eq!(session.writes_count(), 1);
        assert_eq!(session.total_bytes_written(), 23);
        assert!(session.is_started());
        let dbg = format!("{session:?}");
        assert!(dbg.contains("FakeTerminalSession"));
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("utf8_len"));
    }

    #[tokio::test]
    async fn fake_session_closing_rejects_write() {
        let session = FakeTerminalSession::new();
        session.mark_closing();
        assert!(session.is_closing());
        assert_eq!(session.write(b"x").await, Err(TerminalError::Closing));
        assert_eq!(session.writes_count(), 0);
    }

    #[tokio::test]
    async fn fake_session_close_after_n_writes_then_rejects() {
        let session = FakeTerminalSession::new();
        session.close_after_n_writes(1);
        session.write_bytes_sync(b"first").unwrap();
        assert!(session.is_closing());
        assert_eq!(session.write_bytes_sync(b"second"), Err(TerminalError::Closing));
        assert_eq!(session.writes_count(), 1);
        let dbg = format!("{session:?}");
        assert!(!dbg.contains("first"));
    }
}
