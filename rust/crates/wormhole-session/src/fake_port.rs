//! In-memory serial port for fake connectors (no COM device).

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use wormhole_serial::{Result as SerialResult, SerialError, SerialPortHandle};

struct Inner {
    closed: bool,
    dsr: bool,
    dtr: bool,
    read_buf: Vec<u8>,
    written: Vec<u8>,
}

/// Controllable [`SerialPortHandle`] for unit tests.
pub struct NamedFakeSerialPort {
    name: String,
    inner: Arc<Mutex<Inner>>,
}

impl NamedFakeSerialPort {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: Arc::new(Mutex::new(Inner {
                closed: false,
                dsr: true,
                dtr: false,
                read_buf: Vec::new(),
                written: Vec::new(),
            })),
        }
    }
}

impl SerialPortHandle for NamedFakeSerialPort {
    fn port_name(&self) -> &str {
        &self.name
    }

    fn dsr_holding(&mut self) -> SerialResult<bool> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.closed {
            return Err(SerialError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "serial port is closed",
            )));
        }
        Ok(g.dsr)
    }

    fn set_dtr(&mut self, enabled: bool) -> SerialResult<()> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.closed {
            return Err(SerialError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "serial port is closed",
            )));
        }
        g.dtr = enabled;
        let _ = g.dtr;
        Ok(())
    }

    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = SerialResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            {
                let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                if g.closed {
                    return Err(SerialError::Io(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "serial port is closed",
                    )));
                }
                if !g.read_buf.is_empty() {
                    let n = buf.len().min(g.read_buf.len());
                    buf[..n].copy_from_slice(&g.read_buf[..n]);
                    g.read_buf.drain(..n);
                    return Ok(n);
                }
            }
            tokio::task::yield_now().await;
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if g.closed {
                return Ok(0);
            }
            let n = buf.len().min(g.read_buf.len());
            if n > 0 {
                buf[..n].copy_from_slice(&g.read_buf[..n]);
                g.read_buf.drain(..n);
            }
            Ok(n)
        })
    }

    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = SerialResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if g.closed {
                return Err(SerialError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "serial port is closed",
                )));
            }
            g.written.extend_from_slice(data);
            Ok(())
        })
    }

    fn flush(&mut self) -> Pin<Box<dyn std::future::Future<Output = SerialResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn close(&mut self) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.closed = true;
    }

    fn is_closed(&self) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).closed
    }
}
