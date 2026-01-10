//! noiseStream - AsyncRead/AsyncWrite adapter for Noise-encrypted WebSocket
//!
//! this module provides a stream adapter that bridges websocket binary messages
//! with Noise encryption, presenting an AsyncRead + AsyncWrite interface suitable
//! for running http/2 over the encrypted channel

use bytes::{Buf, BytesMut};
use futures_util::{Sink, Stream};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// a stream that provides AsyncRead + AsyncWrite over a Noise-encrypted WebSocket
///
/// this adapter:
/// - Decrypts incoming WebSocket binary messages and buffers them for reading
/// - Encrypts outgoing data and sends as WebSocket binary messages
///
/// the generic parameters allow this to work with both:
/// - tokio_tungstenite WebSocket streams (for tests/clients)
/// - axum WebSocket streams (for server-side use)
pub struct NoiseStream<R, W, E>
where
    R: Stream<Item = Result<Message, E>> + Unpin,
    W: Sink<Message, Error = E> + Unpin,
    E: std::error::Error + Send,
{
    inner: Arc<Mutex<NoiseStreamInner<R, W, E>>>,
}

struct NoiseStreamInner<R, W, E>
where
    R: Stream<Item = Result<Message, E>> + Unpin,
    W: Sink<Message, Error = E> + Unpin,
    E: std::error::Error + Send,
{
    reader: R,
    writer: W,
    transport: snow::TransportState,
    read_buffer: BytesMut,
    _error: std::marker::PhantomData<E>,
}

impl<R, W, E> NoiseStream<R, W, E>
where
    R: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    W: Sink<Message, Error = E> + Unpin + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    /// create a new NoiseStream wrapping a WebSocket and Noise transport
    ///
    /// # Arguments
    /// * `reader` - The WebSocket message stream (read half)
    /// * `writer` - The WebSocket message sink (write half)
    /// * `transport` - The Noise transport state (after handshake completion)
    pub fn new(reader: R, writer: W, transport: snow::TransportState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NoiseStreamInner {
                reader,
                writer,
                transport,
                read_buffer: BytesMut::new(),
                _error: std::marker::PhantomData,
            })),
        }
    }
}

impl<R, W, E> AsyncRead for NoiseStream<R, W, E>
where
    R: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    W: Sink<Message, Error = E> + Unpin + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = self.inner.clone();

        // try to lock synchronously first
        let mut guard = match inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // if we can't get the lock, wake up and try again later
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // if we have buffered data, return it
        if !guard.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), guard.read_buffer.len());
            buf.put_slice(&guard.read_buffer[..len]);
            guard.read_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        // try to read from websocket
        match Pin::new(&mut guard.reader).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                // decrypt the message
                let mut plaintext = vec![0u8; data.len()];
                match guard.transport.read_message(&data, &mut plaintext) {
                    Ok(len) => {
                        plaintext.truncate(len);
                        // copy what we can to the output buffer
                        let copy_len = std::cmp::min(buf.remaining(), len);
                        buf.put_slice(&plaintext[..copy_len]);
                        // buffer the rest
                        if copy_len < len {
                            guard.read_buffer.extend_from_slice(&plaintext[copy_len..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("noise decrypt failed: {}", e),
                    ))),
                }
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) => {
                // connection closed
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // ignore non-binary messages, try again
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
            Poll::Ready(None) => {
                // stream ended
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, W, E> AsyncWrite for NoiseStream<R, W, E>
where
    R: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    W: Sink<Message, Error = E> + Unpin + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = self.inner.clone();

        let mut guard = match inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // encrypt the data
        let mut ciphertext = vec![0u8; buf.len() + 16]; // 16 bytes for AEAD tag
        match guard.transport.write_message(buf, &mut ciphertext) {
            Ok(len) => {
                ciphertext.truncate(len);

                // check if the sink is ready
                match Pin::new(&mut guard.writer).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        // send the encrypted message
                        match Pin::new(&mut guard.writer)
                            .start_send(Message::Binary(ciphertext.into()))
                        {
                            Ok(()) => Poll::Ready(Ok(buf.len())),
                            Err(e) => {
                                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            Err(e) => Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("noise encrypt failed: {}", e),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.clone();

        let mut guard = match inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match Pin::new(&mut guard.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.clone();

        let mut guard = match inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match Pin::new(&mut guard.writer).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}
