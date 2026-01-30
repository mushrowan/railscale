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

mod http_noise_stream;
mod ws_noise_stream;

use axum::{
    Router,
    body::Body,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use futures_util::StreamExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use railscale_proto::NoiseHandshake;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, trace};
use zeroize::Zeroizing;

use http_noise_stream::HttpNoiseStream;
use ws_noise_stream::ServerNoiseStream;

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
    private_key: Zeroizing<Vec<u8>>,
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
        // tka (tailnet lock) endpoints
        .route("/machine/tka/init/begin", post(super::tka_init_begin))
        .route("/machine/tka/init/finish", post(super::tka_init_finish))
        .route("/machine/tka/bootstrap", post(super::tka_bootstrap))
        .route("/machine/tka/sync/offer", post(super::tka_sync_offer))
        .route("/machine/tka/sync/send", post(super::tka_sync_send))
        .route("/machine/tka/disable", post(super::tka_disable))
        .route("/machine/tka/sign", post(super::tka_sign))
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
    private_key: Zeroizing<Vec<u8>>,
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

    // log handshake metadata only (no content for security)
    let noise_payload = &init_message[5..];

    // log handshake metadata only (no content for security)
    debug!(
        noise_payload_len = noise_payload.len(),
        "Noise initiation payload received"
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

    // log response metadata only (no content for security)
    let response_payload = handshake.write_message(&[])?;

    // log response metadata only (no content for security)
    debug!(
        response_len = response_payload.len(),
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
    // log a short prefix of the client key (not secret, but cleaner logs)
    let key_prefix = if client_key.len() >= 4 {
        format!("{:02x}{:02x}...", client_key[0], client_key[1])
    } else {
        "??".to_string()
    };
    info!(
        client_key_prefix = %key_prefix,
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
        // tka (tailnet lock) endpoints
        .route("/machine/tka/init/begin", post(super::tka_init_begin))
        .route("/machine/tka/init/finish", post(super::tka_init_finish))
        .route("/machine/tka/bootstrap", post(super::tka_bootstrap))
        .route("/machine/tka/sync/offer", post(super::tka_sync_offer))
        .route("/machine/tka/sync/send", post(super::tka_sync_send))
        .route("/machine/tka/disable", post(super::tka_disable))
        .route("/machine/tka/sign", post(super::tka_sign))
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
