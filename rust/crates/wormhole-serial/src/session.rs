//! Serial session mirroring `Services/Serial/SerialSession.cs`.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, Notify};
use wormhole_domain::SerialFlowControlMode;
use wormhole_terminal::{
    channel_stub_pair, TerminalEvent, TerminalEventReceiver, TerminalEventSender, TerminalSession,
    CHANNEL_STUB_CAPACITY,
};

use crate::port::{SerialPortHandle, TokioSerialPort};
use crate::settings::{open_builder, SerialLineSettings, SerialOpenOptions};
use crate::Result;

const STATE_OPEN: u8 = 0;
const STATE_UNEXPECTEDLY_CLOSED: u8 = 1;
const STATE_DISPOSED: u8 = 2;

const UNEXPECTED_CLOSE_DRAIN: Duration = Duration::from_millis(250);

struct Inner {
    port: Mutex<Box<dyn SerialPortHandle>>,
    flow_control: SerialFlowControlMode,
    events_tx: TerminalEventSender,
    events_rx: Mutex<Option<TerminalEventReceiver>>,
    lifecycle: AtomicU8,
    started: AtomicBool,
    reading_paused: AtomicBool,
    /// Bumped on each pause/resume so stale DTR tasks cannot invert line state.
    flow_seq: AtomicU64,
    read_gate: Notify,
    write_lock: Mutex<()>,
}

/// Async serial terminal session.
#[derive(Clone)]
pub struct SerialSession {
    inner: Arc<Inner>,
}

impl SerialSession {
    /// Open a real COM port from resolved settings.
    pub async fn open(
        settings: &SerialLineSettings,
        options: SerialOpenOptions,
    ) -> Result<Self> {
        use tokio_serial::{SerialPort, SerialPortBuilderExt};

        let builder = open_builder(settings)?;
        let mut stream = builder.open_native_async()?;

        if options.rts_when_not_hardware
            && settings.flow_control != SerialFlowControlMode::RtsCts
        {
            let _ = stream.write_request_to_send(true);
        }
        if options.dtr_on_open {
            let _ = stream.write_data_terminal_ready(true);
        }

        Ok(Self::from_port(
            Box::new(TokioSerialPort::new(stream)),
            settings.flow_control,
        ))
    }

    /// Construct from an already-opened port handle (tests / adapters).
    pub fn from_port(port: Box<dyn SerialPortHandle>, flow_control: SerialFlowControlMode) -> Self {
        let (events_tx, events_rx) = channel_stub_pair(CHANNEL_STUB_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                port: Mutex::new(port),
                flow_control,
                events_tx,
                events_rx: Mutex::new(Some(events_rx)),
                lifecycle: AtomicU8::new(STATE_OPEN),
                started: AtomicBool::new(false),
                reading_paused: AtomicBool::new(false),
                flow_seq: AtomicU64::new(0),
                read_gate: Notify::new(),
                write_lock: Mutex::new(()),
            }),
        }
    }

    /// Take the event receiver (once). Call before [`TerminalSession::start`].
    pub async fn take_events(&self) -> Option<TerminalEventReceiver> {
        self.inner.events_rx.lock().await.take()
    }

    fn unavailable(&self) -> bool {
        self.inner.lifecycle.load(Ordering::Acquire) != STATE_OPEN
    }

    fn supports_receive_backpressure(mode: SerialFlowControlMode) -> bool {
        matches!(
            mode,
            SerialFlowControlMode::XonXoff
                | SerialFlowControlMode::RtsCts
                | SerialFlowControlMode::DsrDtr
        )
    }

    async fn wait_for_dsr(&self) -> Result<()> {
        while !self.unavailable() {
            {
                let mut port = self.inner.port.lock().await;
                match port.dsr_holding() {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(_) if self.unavailable() => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn signal_unexpected_close(&self) {
        if self
            .inner
            .lifecycle
            .compare_exchange(
                STATE_OPEN,
                STATE_UNEXPECTEDLY_CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        self.inner.reading_paused.store(false, Ordering::Release);
        let _ = self.inner.flow_seq.fetch_add(1, Ordering::AcqRel);
        self.inner.read_gate.notify_waiters();
        let tx = self.inner.events_tx.clone();
        let started = self.inner.started.load(Ordering::Acquire);
        tokio::spawn(async move {
            if started {
                tokio::time::sleep(UNEXPECTED_CLOSE_DRAIN).await;
            }
            let _ = tx.send(TerminalEvent::Closed).await;
        });
    }

    async fn read_pump(inner: Arc<Inner>) {
        let session = SerialSession {
            inner: Arc::clone(&inner),
        };
        let mut buf = vec![0u8; 8192];
        loop {
            if session.unavailable() {
                break;
            }
            if inner.reading_paused.load(Ordering::Acquire) {
                inner.read_gate.notified().await;
                continue;
            }

            let read_result = {
                let mut port = inner.port.lock().await;
                port.read(&mut buf).await
            };

            match read_result {
                Ok(0) => {
                    session.signal_unexpected_close();
                    break;
                }
                Ok(n) => {
                    if session.unavailable() {
                        break;
                    }
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    if inner.events_tx.send(TerminalEvent::Data(data)).await.is_err() {
                        break;
                    }
                }
                Err(_) if session.unavailable() => break,
                Err(_) => {
                    session.signal_unexpected_close();
                    break;
                }
            }
        }
    }

    /// Dispose the session (best-effort close; does not emit `Closed`).
    pub async fn dispose(&self) {
        if self.inner.lifecycle.swap(STATE_DISPOSED, Ordering::AcqRel) == STATE_DISPOSED {
            return;
        }
        self.inner.reading_paused.store(false, Ordering::Release);
        let _ = self.inner.flow_seq.fetch_add(1, Ordering::AcqRel);
        self.inner.read_gate.notify_waiters();
        let mut port = self.inner.port.lock().await;
        port.close();
    }
}

impl TerminalSession for SerialSession {
    fn is_closing(&self) -> bool {
        self.unavailable()
    }

    fn start(&self) {
        if self.inner.started.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.unavailable() {
            return;
        }
        self.inner.read_gate.notify_one();
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            SerialSession::read_pump(inner).await;
        });
    }

    fn write<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = wormhole_terminal::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.unavailable() || data.is_empty() {
                return Ok(());
            }
            let _guard = self.inner.write_lock.lock().await;
            if self.unavailable() {
                return Ok(());
            }
            if self.inner.flow_control == SerialFlowControlMode::DsrDtr {
                if let Err(e) = self.wait_for_dsr().await {
                    self.signal_unexpected_close();
                    return Err(wormhole_terminal::TerminalError::Other(e.to_string()));
                }
            }
            if self.unavailable() {
                return Ok(());
            }
            let mut port = self.inner.port.lock().await;
            if let Err(e) = port.write(data).await {
                drop(port);
                self.signal_unexpected_close();
                return Err(wormhole_terminal::TerminalError::Other(e.to_string()));
            }
            if let Err(e) = port.flush().await {
                drop(port);
                self.signal_unexpected_close();
                return Err(wormhole_terminal::TerminalError::Other(e.to_string()));
            }
            Ok(())
        })
    }

    fn resize(
        &self,
        _columns: u32,
        _rows: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = wormhole_terminal::Result<()>> + Send + '_>>
    {
        Box::pin(async { Ok(()) })
    }

    fn pause_reading(&self) {
        // With no serial flow-control signal there is no way to slow the peer. Parking the read
        // pump would merely let the finite driver buffer overflow — match C# and keep draining.
        if self.unavailable() || !Self::supports_receive_backpressure(self.inner.flow_control) {
            return;
        }
        if self.inner.reading_paused.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.inner.flow_control != SerialFlowControlMode::DsrDtr {
            return;
        }
        let seq = self.inner.flow_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let inner = Arc::clone(&self.inner);
        let session = self.clone();
        tokio::spawn(async move {
            let mut guard = inner.port.lock().await;
            if inner.flow_seq.load(Ordering::Acquire) != seq {
                return;
            }
            if !inner.reading_paused.load(Ordering::Acquire) {
                return;
            }
            if guard.set_dtr(false).is_err() {
                drop(guard);
                inner.reading_paused.store(false, Ordering::Release);
                session.signal_unexpected_close();
            }
        });
    }

    fn resume_reading(&self) {
        let was_paused = self.inner.reading_paused.swap(false, Ordering::AcqRel);
        if self.unavailable() {
            let _ = self.inner.flow_seq.fetch_add(1, Ordering::AcqRel);
            self.inner.read_gate.notify_waiters();
            return;
        }
        if !was_paused {
            return;
        }
        if self.inner.flow_control != SerialFlowControlMode::DsrDtr {
            self.inner.read_gate.notify_waiters();
            return;
        }
        let seq = self.inner.flow_seq.fetch_add(1, Ordering::AcqRel) + 1;
        let inner = Arc::clone(&self.inner);
        let session = self.clone();
        tokio::spawn(async move {
            let mut guard = inner.port.lock().await;
            if inner.flow_seq.load(Ordering::Acquire) != seq {
                return;
            }
            let dtr_ok = guard.set_dtr(true).is_ok();
            drop(guard);
            // Always open the managed gate (C#): never leave the pump wedged on DTR failure.
            inner.read_gate.notify_waiters();
            if !dtr_ok {
                session.signal_unexpected_close();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SerialError;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use wormhole_terminal::TerminalSession;

    struct FakePortState {
        reads: StdMutex<VecDeque<std::result::Result<Vec<u8>, SerialError>>>,
        written: StdMutex<Vec<u8>>,
        closed: AtomicBool,
        dsr: AtomicBool,
        dtr: AtomicBool,
        fail_dtr: AtomicBool,
        fail_write: AtomicBool,
    }

    struct FakePort {
        name: String,
        state: Arc<FakePortState>,
    }

    impl FakePort {
        fn new() -> (Self, Arc<FakePortState>) {
            let state = Arc::new(FakePortState {
                reads: StdMutex::new(VecDeque::new()),
                written: StdMutex::new(Vec::new()),
                closed: AtomicBool::new(false),
                dsr: AtomicBool::new(true),
                dtr: AtomicBool::new(true),
                fail_dtr: AtomicBool::new(false),
                fail_write: AtomicBool::new(false),
            });
            (
                Self {
                    name: "COM_FAKE".into(),
                    state: Arc::clone(&state),
                },
                state,
            )
        }
    }

    impl SerialPortHandle for FakePort {
        fn port_name(&self) -> &str {
            &self.name
        }

        fn dsr_holding(&mut self) -> Result<bool> {
            if self.state.closed.load(Ordering::Acquire) {
                return Err(SerialError::Closing);
            }
            Ok(self.state.dsr.load(Ordering::Acquire))
        }

        fn set_dtr(&mut self, enabled: bool) -> Result<()> {
            if self.state.closed.load(Ordering::Acquire)
                || self.state.fail_dtr.load(Ordering::Acquire)
            {
                return Err(SerialError::Other("dtr failed".into()));
            }
            self.state.dtr.store(enabled, Ordering::Release);
            Ok(())
        }

        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>>
        {
            Box::pin(async move {
                if self.state.closed.load(Ordering::Acquire) {
                    return Err(SerialError::Closing);
                }
                let next = self.state.reads.lock().unwrap().pop_front();
                match next {
                    None => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if self.state.closed.load(Ordering::Acquire) {
                            Err(SerialError::Closing)
                        } else {
                            Ok(0)
                        }
                    }
                    Some(Ok(bytes)) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        Ok(n)
                    }
                    Some(Err(e)) => Err(e),
                }
            })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if self.state.closed.load(Ordering::Acquire)
                    || self.state.fail_write.load(Ordering::Acquire)
                {
                    return Err(SerialError::Other("write failed".into()));
                }
                self.state.written.lock().unwrap().extend_from_slice(data);
                Ok(())
            })
        }

        fn flush(
            &mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                if self.state.closed.load(Ordering::Acquire) {
                    return Err(SerialError::Other("flush failed".into()));
                }
                Ok(())
            })
        }

        fn close(&mut self) {
            self.state.closed.store(true, Ordering::Release);
        }

        fn is_closed(&self) -> bool {
            self.state.closed.load(Ordering::Acquire)
        }
    }

    #[tokio::test]
    async fn write_success_records_bytes() {
        let (port, state) = FakePort::new();
        let session = SerialSession::from_port(Box::new(port), SerialFlowControlMode::None);
        TerminalSession::write(&session, b"hi").await.unwrap();
        assert_eq!(&state.written.lock().unwrap()[..], b"hi");
        session.dispose().await;
    }

    #[tokio::test]
    async fn dispose_closes_port_without_emitting_closed() {
        let (port, state) = FakePort::new();
        let session = SerialSession::from_port(Box::new(port), SerialFlowControlMode::None);
        let mut events = session.take_events().await.unwrap();
        session.dispose().await;
        assert!(session.is_closing());
        assert!(state.closed.load(Ordering::Acquire));
        // Closed must not be published on local dispose (C# parity).
        let raced = tokio::time::timeout(Duration::from_millis(50), events.recv()).await;
        assert!(raced.is_err() || raced.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_failure_signals_unexpected_close() {
        let (port, state) = FakePort::new();
        state.fail_write.store(true, Ordering::Release);
        let session = SerialSession::from_port(Box::new(port), SerialFlowControlMode::None);
        let mut events = session.take_events().await.unwrap();
        let err = TerminalSession::write(&session, b"hi").await.unwrap_err();
        assert!(matches!(err, wormhole_terminal::TerminalError::Other(_)));
        assert!(session.is_closing());
        let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("timeout")
            .expect("closed event");
        assert_eq!(ev, TerminalEvent::Closed);
    }

    #[tokio::test]
    async fn none_flow_control_ignores_pause() {
        let (port, state) = FakePort::new();
        state.reads.lock().unwrap().push_back(Ok(b"x".to_vec()));
        state.reads.lock().unwrap().push_back(Ok(b"y".to_vec()));
        let session =
            SerialSession::from_port(Box::new(port), SerialFlowControlMode::None);
        let mut events = session.take_events().await.unwrap();
        TerminalSession::start(&session);
        TerminalSession::pause_reading(&session);
        // Pump must still deliver (pause is a no-op without backpressure support).
        let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(ev, TerminalEvent::Data(_)));
        session.dispose().await;
    }

    #[tokio::test]
    async fn dsr_dtr_pause_resume_toggles_dtr_with_generation() {
        let (port, state) = FakePort::new();
        let session =
            SerialSession::from_port(Box::new(port), SerialFlowControlMode::DsrDtr);
        assert!(state.dtr.load(Ordering::Acquire));
        TerminalSession::pause_reading(&session);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!state.dtr.load(Ordering::Acquire));
        TerminalSession::resume_reading(&session);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(state.dtr.load(Ordering::Acquire));
        // Rapid pause then resume: generation must leave DTR asserted (resumed).
        TerminalSession::pause_reading(&session);
        TerminalSession::resume_reading(&session);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(state.dtr.load(Ordering::Acquire));
        assert!(!session.is_closing());
        session.dispose().await;
    }

    #[tokio::test]
    async fn dsr_query_failure_signals_unexpected_close() {
        struct FailDsrPort;
        impl SerialPortHandle for FailDsrPort {
            fn port_name(&self) -> &str {
                "COM_FAIL"
            }
            fn dsr_holding(&mut self) -> Result<bool> {
                Err(SerialError::Other("dsr failed".into()))
            }
            fn set_dtr(&mut self, _: bool) -> Result<()> {
                Ok(())
            }
            fn read<'a>(
                &'a mut self,
                _: &'a mut [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>>
            {
                Box::pin(async { Ok(0) })
            }
            fn write<'a>(
                &'a mut self,
                _: &'a [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
            {
                Box::pin(async { Ok(()) })
            }
            fn flush(
                &mut self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>
            {
                Box::pin(async { Ok(()) })
            }
            fn close(&mut self) {}
            fn is_closed(&self) -> bool {
                false
            }
        }

        let session =
            SerialSession::from_port(Box::new(FailDsrPort), SerialFlowControlMode::DsrDtr);
        let mut events = session.take_events().await.unwrap();
        let err = TerminalSession::write(&session, b"x").await.unwrap_err();
        assert!(matches!(err, wormhole_terminal::TerminalError::Other(_)));
        assert!(session.is_closing());
        let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev, TerminalEvent::Closed);
    }

    #[tokio::test]
    async fn open_missing_port_fails() {
        // Valid COM shape so we exercise OS open failure, not name validation.
        let settings = SerialLineSettings::from_optional(
            "COM199",
            Some(9600),
            Some(8),
            None,
            None,
            None,
        )
        .unwrap();
        let err = match SerialSession::open(&settings, SerialOpenOptions::default()).await {
            Ok(_) => panic!("expected open to fail"),
            Err(e) => e,
        };
        assert!(matches!(err, SerialError::Port(_)) || matches!(err, SerialError::Io(_)));
    }
}
