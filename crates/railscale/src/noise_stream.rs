//! noisestream - asyncread/asyncwrite adapter for noise-encrypted websocket.
//!
//! this module provides a stream adapter that bridges websocket binary messages
//! ## Frame Size Limits
//! for running HTTP/2 over the encrypted channel.
//!tailscale's Noise transport has strict frame size limits:
//! - Max plaintext per frame: 4077 bytes
//!- Max ciphertext per frame: 4093 bytes (plaintext + 16 byte AEAD tag)
//! - Max frame on wire: 4096 bytes (3 byte header + ciphertext)
//! - Max plaintext per frame: 4077 bytes
//! large writes are automatically chunked into multiple frames to respect these limits
//! - Max frame on wire: 4096 bytes (3 byte header + ciphertext)
//!
//! large writes are automatically chunked into multiple frames to respect these limits.

use bytes::{Buf, BytesMut};

/// maximum plaintext bytes per noise frame (from tailscale's control/controlbase/conn.go).
/// total frame on wire is 4096 bytes: 3-byte header + 4093-byte ciphertext.
/// ciphertext is plaintext + 16-byte poly1305 tag, so max plaintext is 4077.
const MAX_PLAINTEXT_SIZE: usize = 4077;
use futures_util::{Sink, Stream};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// a stream that provides asyncread + asyncwrite over a noise-encrypted websocket.
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
    /// create a new noisestream wrapping a websocket and noise transport.
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

        // chunk large writes to respect tailscale's frame size limits
        let to_write = std::cmp::min(buf.len(), MAX_PLAINTEXT_SIZE);
        let chunk = &buf[..to_write];

        // encrypt the chunk (16 bytes for AEAD tag)
        let mut ciphertext = vec![0u8; chunk.len() + 16];
        match guard.transport.write_message(chunk, &mut ciphertext) {
            Ok(len) => {
                ciphertext.truncate(len);

                // check if the sink is ready
                match Pin::new(&mut guard.writer).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        // send the encrypted message
                        match Pin::new(&mut guard.writer)
                            .start_send(Message::Binary(ciphertext.into()))
                        {
                            Ok(()) => Poll::Ready(Ok(to_write)),
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
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
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
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Builder;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::AsyncWriteExt;

    const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    /// a simple in-memory sink that captures messages for testing
    const MAX_CIPHERTEXT_SIZE: usize = 4093;

    /// a simple in-memory sink that captures messages for testing.
    struct CapturingSink {
        messages: Arc<StdMutex<Vec<Vec<u8>>>>,
    }

    impl futures_util::Sink<Message> for CapturingSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            if let Message::Binary(data) = item {
                self.messages.lock().unwrap().push(data.to_vec());
            }
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    /// creates a completed noise transport pair (client, server).
    fn create_noise_transports() -> (snow::TransportState, snow::TransportState) {
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();

        let server_keypair = Builder::new(params.clone()).generate_keypair().unwrap();
        let client_keypair = Builder::new(params.clone()).generate_keypair().unwrap();

        let mut client = Builder::new(params.clone())
            .local_private_key(&client_keypair.private)
            .unwrap()
            .remote_public_key(&server_keypair.public)
            .unwrap()
            .build_initiator()
            .unwrap();

        let mut server = Builder::new(params)
            .local_private_key(&server_keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();

        // client -> server
        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..len].to_vec();

        let mut buf = vec![0u8; 65535];
        server.read_message(&msg1, &mut buf).unwrap();

        // server -> client
        let mut buf = vec![0u8; 65535];
        let len = server.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..len].to_vec();

        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        (
            client.into_transport_mode().unwrap(),
            server.into_transport_mode().unwrap(),
        )
    }

    /// test that writing more than 4077 bytes produces multiple frames,
    /// each not exceeding MAX_CIPHERTEXT_SIZE.
    #[tokio::test]
    async fn test_large_write_produces_oversized_frame() {
        let (_, server_transport) = create_noise_transports();

        let captured: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = CapturingSink {
            messages: captured.clone(),
        };

        // create a pending reader (won't read in this test)
        let reader = futures_util::stream::pending::<
            Result<Message, tokio_tungstenite::tungstenite::Error>,
        >();

        let mut stream = NoiseStream::new(reader, sink, server_transport);

        // write 10kb of data - this exceeds the max frame size
        let large_data = vec![0xABu8; 10000];
        stream.write_all(&large_data).await.unwrap();
        stream.flush().await.unwrap();

        // with current (broken) implementation: 1 frame with size > MAX_CIPHERTEXT_SIZE
        let messages = captured.lock().unwrap();

        // with current (broken) implementation: 1 frame with size > max_ciphertext_size
        // with fixed implementation: multiple frames, each <= max_ciphertext_size
        let oversized: Vec<_> = messages
            .iter()
            .filter(|m| m.len() > MAX_CIPHERTEXT_SIZE)
            .collect();

        assert!(
            oversized.is_empty(),
            "Found {} oversized frames (max allowed: {} bytes).\n\
             Frame sizes: {:?}\n\
             Noise transport must chunk large writes into frames <= {} bytes",
            oversized.len(),
            MAX_CIPHERTEXT_SIZE,
            messages.iter().map(|m| m.len()).collect::<Vec<_>>(),
            MAX_CIPHERTEXT_SIZE
        );

        // should have multiple frames for 10kb data
        assert!(
            messages.len() >= 3,
            "Expected >= 3 frames for 10KB, got {} frames: {:?}",
            messages.len(),
            messages.iter().map(|m| m.len()).collect::<Vec<_>>()
        );
    }
}
