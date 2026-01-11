//! ts2021 protocol handler for tailscale clients.
//!
//! this module implements the `/ts2021` endpoint that handles
//! both websocket upgrades (for browser clients) and http protocol
//! switch (for native Tailscale clients) with Noise handshakes.
//!
//! ## protocol variants
//!
//! ### WebSocket (browser clients)
//! ```text
//! get /ts2021?x-tailscale-handshake=<base64>
//! upgrade: websocket
//! ```
//!
//! ### http upgrade (native clients)
//! ```text
//! post /ts2021
//! upgrade: tailscale-control-protocol
//! x-tailscale-handshake: <base64>
//! ```
//!
//! ## Frame Size Limits
//!
//! tailscale's noise transport has strict frame size limits:
//! - Max plaintext per frame: 4077 bytes
//! - Max ciphertext per frame: 4093 bytes (plaintext + 16 byte AEAD tag)
//! - Max frame on wire: 4096 bytes (3 byte header + ciphertext)
//!
//! large writes are automatically chunked into multiple frames.

use axum::{
    Router,
    body::Body,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use bytes::{Buf, BytesMut};
use futures_util::StreamExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use railscale_proto::NoiseHandshake;
use serde::Deserialize;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, error, info, trace};

use super::MachineKeyContext;
use crate::AppState;

/// ts2021 message types.
const MSG_TYPE_INITIATION: u8 = 0x01;
const MSG_TYPE_RESPONSE: u8 = 0x02;
#[allow(dead_code)]
const MSG_TYPE_ERROR: u8 = 0x03;
/// post-handshake data record type.
const MSG_TYPE_RECORD: u8 = 0x04;

/// maximum plaintext bytes per noise frame (from tailscale's control/controlbase/conn.go).
const MAX_PLAINTEXT_SIZE: usize = 4077;

/// query parameters for the /ts2021 endpoint.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Ts2021Params {
    /// base64-encoded noise handshake initiation message.
    #[serde(rename = "X-Tailscale-Handshake")]
    pub handshake: Option<String>,
}

/// handle ts2021 protocol upgrade requests.
///
/// this endpoint accepts websocket upgrades and performs the noise
/// protocol handshake to establish an encrypted connection.
///
/// if no websocket upgrade header is present, axum's extractor will
/// automatically return a 400 Bad Request with an appropriate message.
pub async fn ts2021(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    Query(params): Query<Ts2021Params>,
) -> Response {
    let handshake_b64 = params.handshake;
    let private_key = state.noise_private_key.clone();

    ws.protocols(["tailscale-control-protocol"])
        .on_upgrade(move |socket| async move {
            if let Err(e) =
                handle_ts2021_connection(socket, handshake_b64, private_key, state).await
            {
                error!("ts2021 connection error: {}", e);
            }
        })
}

/// handle ts2021 http protocol upgrade requests (native tailscale clients).
///
/// this endpoint handles the `upgrade: tailscale-control-protocol` header
/// used by native Tailscale clients (Linux, macOS, Windows).
///
/// protocol:
/// ```text
/// post /ts2021
/// upgrade: tailscale-control-protocol
/// connection: upgrade
/// x-tailscale-handshake: <base64 noise init>
///
/// response: 101 switching protocols
/// upgrade: tailscale-control-protocol
/// connection: upgrade
///
/// then: noise response + http/2 over noise
/// ```
pub async fn ts2021_http_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::http::Request<Body>,
) -> Response {
    info!("POST /ts2021 - HTTP upgrade request received");
    trace!("headers: {:?}", headers);

    // check for the upgrade header
    let upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !upgrade.eq_ignore_ascii_case("tailscale-control-protocol") {
        info!(upgrade = %upgrade, "Invalid Upgrade header");
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid Upgrade header. Expected: tailscale-control-protocol",
        )
            .into_response();
    }

    // get the handshake data from header
    let Some(handshake_b64) = headers
        .get("X-Tailscale-Handshake")
        .and_then(|v| v.to_str().ok())
    else {
        info!("Missing X-Tailscale-Handshake header");
        return (
            StatusCode::BAD_REQUEST,
            "Missing X-Tailscale-Handshake header",
        )
            .into_response();
    };

    info!(
        handshake_len = handshake_b64.len(),
        "Got X-Tailscale-Handshake, sending 101 Switching Protocols"
    );

    let handshake_b64 = handshake_b64.to_string();
    let private_key = state.noise_private_key.clone();

    // perform the http upgrade
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(request).await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                error!("ts2021 http upgrade failed: {}", e);
                return;
            }
        };

        if let Err(e) =
            handle_ts2021_http_connection(upgraded, handshake_b64, private_key, state).await
        {
            error!("ts2021 http connection error: {}", e);
        }
    });

    // return 101 switching protocols
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "tailscale-control-protocol")
        .header(header::CONNECTION, "upgrade")
        .body(Body::empty())
        .unwrap()
}

/// handle a ts2021 websocket connection.
async fn handle_ts2021_connection(
    mut socket: axum::extract::ws::WebSocket,
    handshake_b64: Option<String>,
    private_key: Vec<u8>,
    state: AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // parse the initiation message from the query parameter
    let Some(handshake_b64) = handshake_b64 else {
        debug!("no handshake data in query param");
        return Err("missing X-Tailscale-Handshake".into());
    };

    // in url query strings, + becomes space, so convert back
    let handshake_b64 = handshake_b64.replace(' ', "+");
    let init_message = base64::engine::general_purpose::STANDARD.decode(&handshake_b64)?;
    debug!("received initiation message: {} bytes", init_message.len());

    // validate message format (101 bytes total)
    // header: [version:2][type:1][len:2] = 5 bytes
    // payload: 96 bytes
    if init_message.len() < 5 {
        return Err("initiation message too short".into());
    }

    let version = u16::from_be_bytes([init_message[0], init_message[1]]);
    let msg_type = init_message[2];
    let payload_len = u16::from_be_bytes([init_message[3], init_message[4]]);

    debug!(
        "initiation: version={}, type={}, payload_len={}",
        version, msg_type, payload_len
    );

    if msg_type != MSG_TYPE_INITIATION {
        return Err(format!("expected initiation type 0x01, got 0x{:02x}", msg_type).into());
    }

    if init_message.len() != 5 + payload_len as usize {
        return Err(format!(
            "message length mismatch: expected {}, got {}",
            5 + payload_len,
            init_message.len()
        )
        .into());
    }

    // extract the noise payload (96 bytes after header)
    let noise_payload = &init_message[5..];

    // create the tailscale prologue for this version
    let prologue = format!("Tailscale Control Protocol v{}", version);

    // create noise responder with prologue
    let mut handshake =
        NoiseHandshake::new_responder_with_prologue(&private_key, prologue.as_bytes())?;

    // process the initiation message
    handshake.read_message(noise_payload)?;

    // generate response message
    let response_payload = handshake.write_message(&[])?;
    debug!(
        "generated response payload: {} bytes",
        response_payload.len()
    );

    // frame the response: [type:1=0x02][len:2][payload]
    let response_len = response_payload.len() as u16;
    let mut response_msg = vec![MSG_TYPE_RESPONSE];
    response_msg.extend_from_slice(&response_len.to_be_bytes());
    response_msg.extend_from_slice(&response_payload);

    debug!("sending response message: {} bytes", response_msg.len());

    // send over websocket
    socket.send(Message::Binary(response_msg.into())).await?;

    // handshake should be complete - convert to transport mode
    if !handshake.is_complete() {
        return Err("handshake not complete after response".into());
    }

    let client_key = handshake
        .remote_static()
        .ok_or("missing client static key")?;
    debug!("client machine key: {} bytes", client_key.len());

    // create machine key context from the noise handshake
    let machine_key_context = MachineKeyContext::from_bytes(client_key);

    let transport = handshake.into_transport()?;

    // split the websocket for bidirectional communication
    let (ws_write, ws_read) = socket.split();

    // create the encrypted stream
    let noise_stream = ServerNoiseStream::new(ws_read, ws_write, transport);

    // create a router for the ts2021 endpoints with state
    let router: Router = Router::new()
        .route("/machine/register", post(super::register))
        .route("/machine/map", post(super::map))
        .with_state(state);

    // run http/2 server over the encrypted stream
    let io = hyper_util::rt::TokioIo::new(noise_stream);
    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let mut router = router.clone();
        let machine_key_context = machine_key_context.clone();
        async move {
            // convert hyper request to axum-compatible request
            let (mut parts, body) = req.into_parts();

            // inject the machine key context from noise handshake
            parts.extensions.insert(machine_key_context);

            let body = Body::new(body);
            let req = Request::from_parts(parts, body);

            tower::Service::call(&mut router, req).await
        }
    });

    // serve http/2 connection
    let mut http2 = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    http2.max_frame_size(16384);

    if let Err(e) = http2.serve_connection(io, service).await {
        debug!("HTTP/2 connection ended: {}", e);
    }

    Ok(())
}

/// handle a ts2021 http upgraded connection (raw tcp stream).
///
/// unlike the websocket handler, this works with a raw byte stream
/// after the HTTP 101 upgrade completes.
async fn handle_ts2021_http_connection(
    upgraded: hyper::upgrade::Upgraded,
    handshake_b64: String,
    private_key: Vec<u8>,
    state: AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // wrap the upgraded connection for tokio compatibility
    let mut io = TokioIo::new(upgraded);

    // decode the initiation message from header
    let init_message = base64::engine::general_purpose::STANDARD.decode(&handshake_b64)?;
    debug!("received initiation message: {} bytes", init_message.len());

    // validate message format
    if init_message.len() < 5 {
        return Err("initiation message too short".into());
    }

    let version = u16::from_be_bytes([init_message[0], init_message[1]]);
    let msg_type = init_message[2];
    let payload_len = u16::from_be_bytes([init_message[3], init_message[4]]);

    debug!(
        "initiation: version={}, type={}, payload_len={}",
        version, msg_type, payload_len
    );

    if msg_type != MSG_TYPE_INITIATION {
        return Err(format!("expected initiation type 0x01, got 0x{:02x}", msg_type).into());
    }

    if init_message.len() != 5 + payload_len as usize {
        return Err(format!(
            "message length mismatch: expected {}, got {}",
            5 + payload_len,
            init_message.len()
        )
        .into());
    }

    // log the noise payload for debugging
    let noise_payload = &init_message[5..];

    // log the noise payload for debugging
    let payload_preview: Vec<String> = noise_payload
        .iter()
        .take(48)
        .map(|b| format!("{:02x}", b))
        .collect();
    debug!(
        noise_payload_len = noise_payload.len(),
        noise_payload_preview = payload_preview.join(" "),
        "Noise initiation payload"
    );

    // create the tailscale prologue for this version
    let prologue = format!("Tailscale Control Protocol v{}", version);
    debug!(prologue = %prologue, "Using prologue");

    // create noise responder with prologue
    let mut handshake =
        NoiseHandshake::new_responder_with_prologue(&private_key, prologue.as_bytes())?;

    // process the initiation message
    debug!("Processing Noise initiation...");
    handshake.read_message(noise_payload)?;
    debug!("Noise initiation processed successfully");

    // generate response message
    let response_payload = handshake.write_message(&[])?;

    // log the response payload
    let resp_preview: Vec<String> = response_payload
        .iter()
        .take(48)
        .map(|b| format!("{:02x}", b))
        .collect();
    debug!(
        response_len = response_payload.len(),
        response_preview = resp_preview.join(" "),
        "Generated Noise response payload"
    );

    // frame the response: [type:1=0x02][len:2][payload]
    let response_len = response_payload.len() as u16;
    let mut response_msg = vec![MSG_TYPE_RESPONSE];
    response_msg.extend_from_slice(&response_len.to_be_bytes());
    response_msg.extend_from_slice(&response_payload);

    info!("sending Noise response: {} bytes", response_msg.len());

    // send response directly over the upgraded connection
    io.write_all(&response_msg).await?;
    io.flush().await?;

    // handshake should be complete
    if !handshake.is_complete() {
        error!("Noise handshake not complete after response!");
        return Err("handshake not complete after response".into());
    }

    let client_key = handshake
        .remote_static()
        .ok_or("missing client static key")?;
    info!(
        client_key = %hex::encode(&client_key),
        "Noise handshake complete, client machine key authenticated"
    );

    // create machine key context from the noise handshake
    let machine_key_context = MachineKeyContext::from_bytes(client_key);

    let transport = handshake.into_transport()?;
    info!("Starting HTTP/2 server over Noise transport");

    // create the encrypted stream for HTTP/2
    let noise_stream = HttpNoiseStream::new(io, transport);

    // create a router for the ts2021 endpoints with state
    let router: Router = Router::new()
        .route("/machine/register", post(super::register))
        .route("/machine/map", post(super::map))
        .with_state(state);

    // run http/2 server over the encrypted stream
    let io = hyper_util::rt::TokioIo::new(noise_stream);
    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let mut router = router.clone();
        let machine_key_context = machine_key_context.clone();
        async move {
            info!(
                method = %req.method(),
                uri = %req.uri(),
                "HTTP/2 request over Noise"
            );
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(machine_key_context);
            let body = Body::new(body);
            let req = Request::from_parts(parts, body);
            tower::Service::call(&mut router, req).await
        }
    });

    // serve http/2 connection
    let mut http2 = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    http2.max_frame_size(16384);

    if let Err(e) = http2.serve_connection(io, service).await {
        debug!("HTTP/2 connection ended: {}", e);
    }

    Ok(())
}

/// http upgraded noise stream wrapper.
///
/// this provides asyncread + asyncwrite over a noise-encrypted raw tcp stream,
/// suitable for running HTTP/2 over the Noise transport after HTTP upgrade.
struct HttpNoiseStream {
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
    fn new(
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
                    // extract the ciphertext
                    let ciphertext = &this.pending_frame[3..total_frame_len];

                    // log detailed ciphertext info
                    let ct_preview_len = std::cmp::min(16, ciphertext.len());
                    let ct_preview: Vec<String> = ciphertext[..ct_preview_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();

                    // also log the last few bytes to detect any corruption
                    let ct_tail_start = ciphertext.len().saturating_sub(16);
                    let ct_tail: Vec<String> = ciphertext[ct_tail_start..]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();

                    debug!(
                        decrypt_count = this.decrypt_count,
                        total_frame_len = total_frame_len,
                        ciphertext_len = ciphertext.len(),
                        ciphertext_head = ct_preview.join(" "),
                        ciphertext_tail = ct_tail.join(" "),
                        pending_frame_capacity = this.pending_frame.capacity(),
                        "poll_read: decrypting frame"
                    );

                    // decrypt
                    match this.transport.decrypt(ciphertext) {
                        Ok(plaintext) => {
                            this.decrypt_count += 1;

                            // log the plaintext preview
                            let pt_preview_len = std::cmp::min(32, plaintext.len());
                            let pt_preview: Vec<String> = plaintext[..pt_preview_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();

                            debug!(
                                decrypt_count = this.decrypt_count,
                                ciphertext_len = ciphertext.len(),
                                plaintext_len = plaintext.len(),
                                plaintext_preview = pt_preview.join(" "),
                                "poll_read: decrypted successfully"
                            );

                            // remove the processed frame from pending_frame
                            this.pending_frame.advance(total_frame_len);

                            // log what's at the start of the next frame (if any)
                            if this.pending_frame.len() >= 16 {
                                let next_preview: Vec<String> = this.pending_frame[..16]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                debug!(
                                    next_frame_preview = next_preview.join(" "),
                                    remaining_bytes = this.pending_frame.len(),
                                    "poll_read: next frame boundary preview"
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
                            // log extensive debugging info on failure
                            let ct_full_preview_len = std::cmp::min(64, msg_len);
                            let ct_full: Vec<String> = this.pending_frame
                                [3..3 + ct_full_preview_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();

                            error!(
                                error = %e,
                                decrypt_count = this.decrypt_count,
                                ciphertext_len = ciphertext.len(),
                                ciphertext_first_64 = ct_full.join(" "),
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

                    // log the raw bytes received
                    let preview_len = std::cmp::min(32, bytes_read.len());
                    let preview: Vec<String> = bytes_read[..preview_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    trace!(
                        bytes_received = bytes_read.len(),
                        first_bytes = preview.join(" "),
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

/// server-side noise stream wrapper for axum websocket.
///
/// this provides asyncread + asyncwrite over an encrypted websocket,
/// suitable for running HTTP/2 over the Noise transport.
struct ServerNoiseStream<R, W> {
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
    fn new(reader: R, writer: W, transport: railscale_proto::NoiseTransport) -> Self {
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
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
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
                        Err(e) => Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string()))),
                    }
                }
                Poll::Ready(Err(e)) => {
                    Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
                }
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
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.writer).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
