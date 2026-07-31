//! Abstract serial port handle so unit tests can avoid real COM devices.

use std::io;
use std::pin::Pin;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::{SerialPort, SerialStream};

use crate::error::SerialError;
use crate::Result;

/// Port operations used by [`crate::SerialSession`] (mirrors C# `ISerialSessionPort`).
pub trait SerialPortHandle: Send {
    fn port_name(&self) -> &str;
    fn dsr_holding(&mut self) -> Result<bool>;
    fn set_dtr(&mut self, enabled: bool) -> Result<()>;
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>>;
    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn flush(&mut self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
    /// Close and release the OS handle (idempotent).
    fn close(&mut self);
    /// True after [`close`](Self::close) (tests / diagnostics).
    fn is_closed(&self) -> bool;
}

/// Live tokio-serial port wrapper.
pub struct TokioSerialPort {
    name: String,
    stream: Option<SerialStream>,
}

impl TokioSerialPort {
    pub fn new(stream: SerialStream) -> Self {
        let name = stream.name().unwrap_or_else(|| "unknown".into());
        Self {
            name,
            stream: Some(stream),
        }
    }

    pub fn into_inner(mut self) -> Option<SerialStream> {
        self.stream.take()
    }

    fn stream_mut(&mut self) -> Result<&mut SerialStream> {
        self.stream.as_mut().ok_or_else(|| {
            SerialError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "serial port is closed",
            ))
        })
    }
}

impl SerialPortHandle for TokioSerialPort {
    fn port_name(&self) -> &str {
        &self.name
    }

    fn dsr_holding(&mut self) -> Result<bool> {
        Ok(self.stream_mut()?.read_data_set_ready()?)
    }

    fn set_dtr(&mut self, enabled: bool) -> Result<()> {
        self.stream_mut()?.write_data_terminal_ready(enabled)?;
        Ok(())
    }

    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let n = self.stream_mut()?.read(buf).await?;
            Ok(n)
        })
    }

    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.stream_mut()?.write_all(data).await?;
            Ok(())
        })
    }

    fn flush(&mut self) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.stream_mut()?.flush().await?;
            Ok(())
        })
    }

    fn close(&mut self) {
        // Dropping the stream releases the OS COM handle (C# `SerialPort.Close`).
        self.stream.take();
    }

    fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
}
