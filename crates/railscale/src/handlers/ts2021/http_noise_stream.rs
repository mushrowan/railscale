//! http upgraded noise stream implementation.
//!
//! this module provides `httpnoisestream`, which wraps a raw tcp stream
//! (from an http upgrade) with noise encryption for running http/2 over
//! the encrypted transport.

use bytes::{Buf, BytesMut};
use hyper_util::rt::TokioIo;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error, trace};

use super::{MAX_PLAINTEXT_SIZE, MSG_TYPE_RECORD};

/// http upgraded noise stream wrapper.
///
/// this provides asyncread + asyncwrite over a noise-encrypted raw tcp stream,
/// suitable for running HTTP/2 over the Noise transport after HTTP upgrade.
pub(super) struct HttpNoiseStream {
    io: TokioIo<hyper::upgrade::Upgraded>,
    transport: railscale_proto::NoiseTransport,
    /// buffer for decrypted plaintext that hasn't been returned to caller yet
    read_buffer: BytesMut,
    /// buffer for accumulating incomplete noise frames from the wire
    pending_frame: BytesMut,
    /// counter for decrypt operations (for debugging)
    decrypt_count: u64,
    /// counter for encrypt operations (for debugging)
    encrypt_count: u64,
}

impl HttpNoiseStream {
    pub(super) fn new(
        io: TokioIo<hyper::upgrade::Upgraded>,
        transport: railscale_proto::NoiseTransport,
    ) -> Self {
        Self {
            io,
            transport,
            read_buffer: BytesMut::new(),
            pending_frame: BytesMut::new(),
            decrypt_count: 0,
            encrypt_count: 0,
        }
    }
}

impl AsyncRead for HttpNoiseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // return buffered decrypted data first
        if !this.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
            trace!(
                buffered_len = this.read_buffer.len(),
                returning = len,
                "poll_read: returning buffered data"
            );
            buf.put_slice(&this.read_buffer[..len]);
            this.read_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        // read data into pending_frame buffer until we have a complete frame
        // frame format: [type:1][len:2 be][encrypted data]
        loop {
            // check if we have enough data for the header
            if this.pending_frame.len() >= 3 {
                let msg_type = this.pending_frame[0];
                let msg_len =
                    u16::from_be_bytes([this.pending_frame[1], this.pending_frame[2]]) as usize;
                let total_frame_len = 3 + msg_len;

                trace!(
                    pending_len = this.pending_frame.len(),
                    msg_type = format!("0x{:02x}", msg_type),
                    msg_len = msg_len,
                    total_frame_len = total_frame_len,
                    header_bytes = format!(
                        "{:02x} {:02x} {:02x}",
                        this.pending_frame[0], this.pending_frame[1], this.pending_frame[2]
                    ),
                    "poll_read: parsing frame header"
                );

                if msg_type != MSG_TYPE_RECORD {
                    // log the first few bytes for debugging
                    let preview_len = std::cmp::min(16, this.pending_frame.len());
                    let preview: Vec<String> = this.pending_frame[..preview_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    error!(
                        expected = format!("0x{:02x}", MSG_TYPE_RECORD),
                        got = format!("0x{:02x}", msg_type),
                        pending_len = this.pending_frame.len(),
                        first_bytes = preview.join(" "),
                        "poll_read: unexpected message type"
                    );
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "unexpected Noise message type: expected 0x{:02x}, got 0x{:02x}",
                            MSG_TYPE_RECORD, msg_type
                        ),
                    )));
                }

                // check if we have the complete frame
                if this.pending_frame.len() >= total_frame_len {
                    // log frame metadata only (no content for security)
                    let ciphertext = &this.pending_frame[3..total_frame_len];

                    // log frame metadata only (no content for security)
                    debug!(
                        decrypt_count = this.decrypt_count,
                        total_frame_len = total_frame_len,
                        ciphertext_len = ciphertext.len(),
                        pending_frame_capacity = this.pending_frame.capacity(),
                        "poll_read: decrypting frame"
                    );

                    // decrypt
                    match this.transport.decrypt(ciphertext) {
                        Ok(plaintext) => {
                            this.decrypt_count += 1;

                            // log decrypt success with lengths only (no content for security)
                            debug!(
                                decrypt_count = this.decrypt_count,
                                ciphertext_len = ciphertext.len(),
                                plaintext_len = plaintext.len(),
                                "poll_read: decrypted successfully"
                            );

                            // remove the processed frame from pending_frame
                            this.pending_frame.advance(total_frame_len);

                            // log remaining buffer size (no content)
                            if !this.pending_frame.is_empty() {
                                trace!(
                                    remaining_bytes = this.pending_frame.len(),
                                    "poll_read: remaining pending data"
                                );
                            }

                            // copy decrypted data to output
                            let copy_len = std::cmp::min(buf.remaining(), plaintext.len());
                            buf.put_slice(&plaintext[..copy_len]);

                            // buffer any overflow
                            if copy_len < plaintext.len() {
                                this.read_buffer.extend_from_slice(&plaintext[copy_len..]);
                                trace!(
                                    buffered = plaintext.len() - copy_len,
                                    "poll_read: buffered overflow"
                                );
                            }

                            trace!(
                                remaining_pending = this.pending_frame.len(),
                                returned = copy_len,
                                "poll_read: frame complete"
                            );

                            return Poll::Ready(Ok(()));
                        }
                        Err(e) => {
                            // log error with metadata only (no content for security)
                            error!(
                                error = %e,
                                decrypt_count = this.decrypt_count,
                                ciphertext_len = ciphertext.len(),
                                pending_frame_len = this.pending_frame.len(),
                                "poll_read: decrypt failed"
                            );
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                format!("noise decrypt failed: {}", e),
                            )));
                        }
                    }
                } else {
                    trace!(
                        have = this.pending_frame.len(),
                        need = total_frame_len,
                        "poll_read: incomplete frame, need more data"
                    );
                }
            } else if !this.pending_frame.is_empty() {
                trace!(
                    pending_len = this.pending_frame.len(),
                    "poll_read: partial header, need more data"
                );
            }

            // need more data - read from the underlying stream
            let mut tmp_buf = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut tmp_buf);

            match Pin::new(&mut this.io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled();
                    if bytes_read.is_empty() {
                        // eof
                        if this.pending_frame.is_empty() {
                            debug!("poll_read: clean EOF");
                            return Poll::Ready(Ok(()));
                        } else {
                            error!(
                                pending_len = this.pending_frame.len(),
                                "poll_read: EOF with incomplete frame"
                            );
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "connection closed with incomplete Noise frame",
                            )));
                        }
                    }

                    // log wire read with lengths only (no content for security)
                    trace!(
                        bytes_received = bytes_read.len(),
                        pending_before = this.pending_frame.len(),
                        "poll_read: received data from wire"
                    );

                    // append to pending_frame and loop to check if we have a complete frame
                    this.pending_frame.extend_from_slice(bytes_read);
                }
                Poll::Ready(Err(e)) => {
                    error!(error = %e, "poll_read: underlying read error");
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for HttpNoiseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // chunk large writes to respect tailscale's frame size limits
        let to_write = std::cmp::min(buf.len(), MAX_PLAINTEXT_SIZE);
        let chunk = &buf[..to_write];

        // encrypt the chunk
        let ciphertext = match self.transport.encrypt(chunk) {
            Ok(ct) => ct,
            Err(e) => {
                error!(error = %e, encrypt_count = self.encrypt_count, "poll_write: encrypt failed");
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("noise encrypt failed: {}", e),
                )));
            }
        };

        self.encrypt_count += 1;

        // build the framed message: [type:1][len:2][ciphertext]
        let len = ciphertext.len() as u16;
        let mut msg = Vec::with_capacity(3 + ciphertext.len());
        msg.push(MSG_TYPE_RECORD); // 0x04 for data records
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&ciphertext);

        debug!(
            encrypt_count = self.encrypt_count,
            frame_len = msg.len(),
            header = format!("{:02x} {:02x} {:02x}", msg[0], msg[1], msg[2]),
            plaintext_len = to_write,
            ciphertext_len = ciphertext.len(),
            "poll_write: sending frame"
        );

        // write to the underlying stream
        match Pin::new(&mut self.io).poll_write(cx, &msg) {
            Poll::Ready(Ok(written)) => {
                trace!(
                    written = written,
                    expected = msg.len(),
                    "poll_write: wrote to underlying stream"
                );
                Poll::Ready(Ok(to_write))
            }
            Poll::Ready(Err(e)) => {
                error!(error = %e, "poll_write: underlying write error");
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
