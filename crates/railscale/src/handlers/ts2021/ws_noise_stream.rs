//! webSocket Noise stream implementation
//!
//! this module provides `ServerNoiseStream`, which wraps an axum WebSocket
//! with Noise encryption for running http/2 over the encrypted transport

use axum::extract::ws::Message;
use bytes::{Buf, BytesMut};

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::MAX_PLAINTEXT_SIZE;

/// server-side Noise stream wrapper for axum WebSocket
///
/// this provides AsyncRead + AsyncWrite over an encrypted WebSocket,
/// suitable for running http/2 over the Noise transport
pub(super) struct ServerNoiseStream<R, W> {
    reader: R,
    writer: W,
    transport: railscale_proto::NoiseTransport,
    read_buffer: BytesMut,
}

impl<R, W> ServerNoiseStream<R, W>
where
    R: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
    W: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    pub(super) fn new(reader: R, writer: W, transport: railscale_proto::NoiseTransport) -> Self {
        Self {
            reader,
            writer,
            transport,
            read_buffer: BytesMut::new(),
        }
    }
}

impl<R, W> AsyncRead for ServerNoiseStream<R, W>
where
    R: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
    W: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // if we have buffered data, return it
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..len]);
            self.read_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        // try to read from websocket
        match Pin::new(&mut self.reader).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                // decrypt the message
                match self.transport.decrypt(&data) {
                    Ok(plaintext) => {
                        // copy what we can to the output buffer
                        let copy_len = std::cmp::min(buf.remaining(), plaintext.len());
                        buf.put_slice(&plaintext[..copy_len]);
                        // buffer the rest
                        if copy_len < plaintext.len() {
                            self.read_buffer.extend_from_slice(&plaintext[copy_len..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("noise decrypt failed: {}", e),
                    ))),
                }
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Ok(_))) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, W> AsyncWrite for ServerNoiseStream<R, W>
where
    R: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
    W: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // chunk large writes to respect tailscale's frame size limits
        let to_write = std::cmp::min(buf.len(), MAX_PLAINTEXT_SIZE);
        let chunk = &buf[..to_write];

        // encrypt the chunk
        match self.transport.encrypt(chunk) {
            Ok(ciphertext) => match Pin::new(&mut self.writer).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match Pin::new(&mut self.writer).start_send(Message::Binary(ciphertext.into()))
                    {
                        Ok(()) => Poll::Ready(Ok(to_write)),
                        Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                Poll::Pending => Poll::Pending,
            },
            Err(e) => Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("noise encrypt failed: {}", e),
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.writer).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}
