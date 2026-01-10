//! ts2021 protocol handler for tailscale clients.
//!
//! this module implements the `/ts2021` endpoint that handles
//! websocket upgrades and noise protocol handshakes for the
//! tailscale control protocol.

use axum::{
    Router,
    body::Body,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    response::Response,
    routing::post,
};
use base64::Engine;
use bytes::{Buf, BytesMut};
use futures_util::StreamExt;
use hyper::Request;
use railscale_proto::NoiseHandshake;
use serde::Deserialize;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
            if let Err(e) =
                handle_ts2021_connection(socket, handshake_b64, private_key, state).await
            {
                error!("ts2021 connection error: {}", e);
            }
        })
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
        async move {
            // convert hyper request to axum-compatible request
            let (parts, body) = req.into_parts();
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
        // encrypt the data
        match self.transport.encrypt(buf) {
            Ok(ciphertext) => match Pin::new(&mut self.writer).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match Pin::new(&mut self.writer).start_send(Message::Binary(ciphertext.into()))
                    {
                        Ok(()) => Poll::Ready(Ok(buf.len())),
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
