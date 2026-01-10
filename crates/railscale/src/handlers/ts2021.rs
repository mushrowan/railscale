//! ts2021 protocol handler for tailscale clients.
//!
//! this module implements the `/ts2021` endpoint that handles
//! websocket upgrades and noise protocol handshakes for the
//! tailscale control protocol.

use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    response::Response,
};
use base64::Engine;
use railscale_proto::NoiseHandshake;
use serde::Deserialize;
use tracing::{debug, error};

use crate::AppState;

/// ts2021 message types.
const MSG_TYPE_INITIATION: u8 = 0x01;
const MSG_TYPE_RESPONSE: u8 = 0x02;

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
            if let Err(e) = handle_ts2021_connection(socket, handshake_b64, private_key).await {
                error!("ts2021 connection error: {}", e);
            }
        })
}

/// handle a ts2021 websocket connection.
async fn handle_ts2021_connection(
    mut socket: axum::extract::ws::WebSocket,
    handshake_b64: Option<String>,
    private_key: Vec<u8>,
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

    // process the initiation message
    let noise_payload = &init_message[5..];

    // generate response message
    let prologue = format!("Tailscale Control Protocol v{}", version);

    // create noise responder with prologue
    let mut handshake =
        NoiseHandshake::new_responder_with_prologue(&private_key, prologue.as_bytes())?;

    // frame the response: [type:1=0x02][len:2][payload]
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

    // TODO: continue with http/2 over noise transport
    // for now, the handshake is complete - future work will add the http/2 layer

    Ok(())
}
