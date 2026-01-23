use std::collections::HashMap;
use std::fs;
use std::io::BufReader as StdBufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use color_eyre::eyre::{self, Context as EyreContext, eyre};
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore, OsRng},
};
use hex::ToHex;
use httparse;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{self, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{
    self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info};

use railscale_proto::Keypair;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const DERP_MAGIC: &[u8; 8] = b"DERP\xF0\x9F\x94\x91";
const DERP_PROTOCOL_VERSION: u32 = 2;
const MAX_HTTP_REQUEST_SIZE: usize = 8 * 1024;
/// maximum derp frame payload size (64kb). prevents memory exhaustion from malicious frames.
const MAX_FRAME_PAYLOAD_SIZE: usize = 64 * 1024;

/// tls assets used by the embedded derp listener.
pub struct DerpTlsAssets {
    /// the rustls server configuration with loaded certificates.
    pub tls_config: Arc<ServerConfig>,
    /// sha-256 fingerprint of the certificate (hex-encoded).
    pub fingerprint: String,
}

/// create a tls configuration for the embedded derp server, generating a
/// self-signed certificate if necessary.
pub fn load_or_generate_derp_tls(
    cert_path: &Path,
    key_path: &Path,
    hosts: &[String],
) -> eyre::Result<DerpTlsAssets> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).wrap_err("failed to create DERP certificate directory")?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).wrap_err("failed to create DERP key directory")?;
    }

    let (cert_chain, private_key, der_bytes) = if cert_path.exists() && key_path.exists() {
        load_existing_cert(cert_path, key_path)?
    } else {
        generate_new_cert(cert_path, key_path, hosts)?
    };

    let fingerprint = compute_fingerprint(&der_bytes);
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .wrap_err("failed to build DERP TLS config")?;

    Ok(DerpTlsAssets {
        tls_config: Arc::new(config),
        fingerprint,
    })
}

fn load_existing_cert(
    cert_path: &Path,
    key_path: &Path,
) -> eyre::Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<u8>,
)> {
    let mut cert_reader =
        StdBufReader::new(fs::File::open(cert_path).wrap_err("failed to open DERP cert")?);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("failed to parse DERP certificate")?;
    if certs.is_empty() {
        return Err(eyre!("DERP certificate file is empty"));
    }

    let mut key_reader =
        StdBufReader::new(fs::File::open(key_path).wrap_err("failed to open DERP key")?);
    let keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("failed to parse DERP key")?;
    let key: PrivateKeyDer<'static> = keys
        .into_iter()
        .next()
        .map(|k| k.into())
        .ok_or_else(|| eyre!("DERP key file did not contain a PKCS#8 private key"))?;

    let der_bytes = certs[0].to_vec();
    Ok((certs, key, der_bytes))
}

fn generate_new_cert(
    cert_path: &Path,
    key_path: &Path,
    hosts: &[String],
) -> eyre::Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<u8>,
)> {
    // filter out empty hosts
    let san_names: Vec<String> = hosts
        .iter()
        .filter(|h| !h.trim().is_empty())
        .cloned()
        .collect();

    // generate self-signed certificate
    let certified_key =
        generate_simple_self_signed(san_names).wrap_err("failed to generate DERP certificate")?;

    // serialize to pem and write to files
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();
    fs::write(cert_path, &cert_pem).wrap_err("failed to write DERP certificate")?;
    fs::write(key_path, &key_pem).wrap_err("failed to write DERP key")?;

    // get der bytes for fingerprint calculation
    let der_bytes = certified_key.cert.der().to_vec();
    let cert_der = CertificateDer::from(der_bytes.clone());
    let key_der = PrivateKeyDer::try_from(certified_key.signing_key.serialized_der().to_vec())
        .map_err(|_| eyre!("failed to convert key to DER"))?;

    Ok((vec![cert_der], key_der, der_bytes))
}

fn compute_fingerprint(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hasher.finalize().encode_hex()
}

/// options for running the embedded derp listener.
pub struct DerpListenerConfig {
    /// the address to bind the derp listener to.
    pub listen_addr: SocketAddr,
    /// tls configuration for the listener.
    pub tls_config: Arc<ServerConfig>,
    /// the derp server instance to handle connections.
    pub server: EmbeddedDerpServer,
    /// maximum concurrent connections. prevents resource exhaustion from too many clients.
    pub max_connections: usize,
}

/// spawn the embedded derp listener in a background task.
///
/// returns a join handle for the listener task.
pub async fn spawn_derp_listener(config: DerpListenerConfig) -> eyre::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .wrap_err("failed to bind DERP listener")?;
    info!(
        addr = %config.listen_addr,
        max_connections = config.max_connections,
        "embedded DERP listening"
    );

    let acceptor = TlsAcceptor::from(config.tls_config);
    let derp_server = config.server.clone();
    let connection_semaphore = Arc::new(Semaphore::new(config.max_connections));

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // try to acquire a permit - if at capacity, reject the connection
                    let permit = match connection_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            debug!(peer = %addr, "DERP connection rejected: at capacity");
                            // drop the stream to close the connection
                            drop(stream);
                            continue;
                        }
                    };

                    let acceptor = acceptor.clone();
                    let server = derp_server.clone();
                    tokio::spawn(async move {
                        // permit is held for the duration of the connection
                        let _permit = permit;
                        if let Err(err) = handle_derp_stream(stream, acceptor, server, addr).await {
                            debug!(?err, peer = %addr, "DERP connection ended with error");
                        }
                    });
                }
                Err(err) => {
                    error!(?err, "DERP listener accept failed");
                }
            }
        }
    });

    Ok(handle)
}

async fn handle_derp_stream(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    server: EmbeddedDerpServer,
    remote_addr: SocketAddr,
) -> Result<(), DerpServerError> {
    let tls_stream = acceptor.accept(stream).await?;
    process_http_upgrade(tls_stream, server, remote_addr).await
}

#[derive(Debug)]
enum DerpRequest {
    /// normal derp upgrade request
    Upgrade { fast_start: bool },
    /// latency check endpoint (returns 200 ok immediately)
    LatencyCheck,
}

async fn process_http_upgrade(
    mut stream: TlsStream<TcpStream>,
    server: EmbeddedDerpServer,
    remote_addr: SocketAddr,
) -> Result<(), DerpServerError> {
    let (request_bytes, leftover) = read_http_request(&mut stream).await?;
    let request = parse_derp_request(&request_bytes)?;

    match request {
        DerpRequest::LatencyCheck => {
            // return 200 ok for latency checks (used by netcheck)
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            stream.flush().await?;
            Ok(())
        }
        DerpRequest::Upgrade { fast_start } => {
            if !fast_start {
                write_upgrade_response(&mut stream, &server).await?;
            }

            let prefixed = PrefixedStream::new(stream, leftover);
            server.handle_connection(prefixed, Some(remote_addr)).await
        }
    }
}

async fn read_http_request<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), DerpServerError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut temp = [0u8; 1024];

    loop {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            return Err(DerpServerError::Handshake(
                "connection closed during HTTP upgrade".into(),
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(idx) = find_header_terminator(&buffer) {
            let mut leftover = buffer.split_off(idx + 4);
            let request = buffer;
            return Ok((request, std::mem::take(&mut leftover)));
        }
        if buffer.len() > MAX_HTTP_REQUEST_SIZE {
            return Err(DerpServerError::Handshake("HTTP request too large".into()));
        }
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|slice| slice == b"\r\n\r\n")
}

fn parse_derp_request(buf: &[u8]) -> Result<DerpRequest, DerpServerError> {
    let mut headers = [httparse::Header {
        name: "",
        value: &[],
    }; 32];
    let mut req = httparse::Request::new(&mut headers);
    let status = req
        .parse(buf)
        .map_err(|e| DerpServerError::Handshake(format!("failed to parse request: {e}")))?;
    if status.is_partial() {
        return Err(DerpServerError::Handshake("incomplete HTTP request".into()));
    }

    if req.method != Some("GET") {
        return Err(DerpServerError::Handshake("unsupported HTTP method".into()));
    }

    // handle latency check endpoints (used by netcheck)
    match req.path {
        Some("/derp/probe") | Some("/derp/latency-check") => {
            return Ok(DerpRequest::LatencyCheck);
        }
        Some("/derp") => {}
        _ => {
            return Err(DerpServerError::Handshake("unknown DERP endpoint".into()));
        }
    }

    let upgrade =
        header_eq(&headers, "Upgrade", "derp") || header_eq(&headers, "Upgrade", "websocket");
    if !upgrade {
        return Err(DerpServerError::Handshake(
            "missing Upgrade: DERP header".into(),
        ));
    }
    if !header_contains_token(&headers, "Connection", "upgrade") {
        return Err(DerpServerError::Handshake(
            "missing Connection: Upgrade header".into(),
        ));
    }

    let fast_start = header_eq(&headers, "Derp-Fast-Start", "1");
    Ok(DerpRequest::Upgrade { fast_start })
}

fn header_eq(headers: &[httparse::Header<'_>], name: &str, expected: &str) -> bool {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.eq_ignore_ascii_case(expected.as_bytes()))
        .unwrap_or(false)
}

fn header_contains_token(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| {
            h.value
                .split(|b| *b == b',' || *b == b' ')
                .any(|part| part.eq_ignore_ascii_case(token.as_bytes()))
        })
        .unwrap_or(false)
}

async fn write_upgrade_response<S>(stream: &mut S, server: &EmbeddedDerpServer) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: {}\r\nDerp-Public-Key: {}\r\n\r\n",
        DERP_PROTOCOL_VERSION,
        server.crypto.public_bytes.encode_hex::<String>()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// embedded derp relay server.
///
/// handles derp protocol connections for relaying encrypted traffic between
/// tailscale clients when direct connections are not possible.
#[derive(Clone)]
pub struct EmbeddedDerpServer {
    crypto: DerpKeyMaterial,
    state: Arc<DerpServerState>,
    idle_timeout: Option<Duration>,
}

impl EmbeddedDerpServer {
    /// create a new derp server with the given options.
    pub fn new(options: EmbeddedDerpOptions) -> Self {
        let idle_timeout = if options.idle_timeout_secs > 0 {
            Some(Duration::from_secs(options.idle_timeout_secs))
        } else {
            None
        };
        Self {
            crypto: DerpKeyMaterial::new(options.keypair),
            state: Arc::new(DerpServerState::default()),
            idle_timeout,
        }
    }

    /// handle a single derp connection.
    ///
    /// performs the derp handshake and then relays frames between clients.
    pub async fn handle_connection<S>(
        &self,
        stream: S,
        remote_addr: Option<SocketAddr>,
    ) -> Result<(), DerpServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader_half, writer_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader_half);
        let mut writer = BufWriter::new(writer_half);

        self.send_server_key(&mut writer).await?;
        let client_key = self.receive_client_info(&mut reader).await?;
        self.send_server_info(&mut writer, &client_key).await?;

        if let Some(addr) = remote_addr {
            debug!(peer = %addr, client = %short_key(&client_key), "DERP client connected");
        }

        let (tx, rx) = mpsc::channel(64);
        {
            let mut guard = self.state.clients.lock().await;
            guard.insert(client_key, tx.clone());
        }

        let write_task = tokio::spawn(async move {
            write_loop(writer, rx).await;
        });

        let read_result = self.read_loop(&mut reader, client_key, tx.clone()).await;

        {
            let mut guard = self.state.clients.lock().await;
            guard.remove(&client_key);
        }

        drop(tx);
        let _ = write_task.await;

        if let Some(addr) = remote_addr {
            debug!(peer = %addr, client = %short_key(&client_key), "DERP client disconnected");
        }

        read_result
    }

    // ... rest of methods remain largely unchanged ...

    async fn read_loop<R>(
        &self,
        reader: &mut BufReader<R>,
        client_key: [u8; 32],
        outbound: mpsc::Sender<ServerFrame>,
    ) -> Result<(), DerpServerError>
    where
        R: AsyncRead + Unpin + Send,
    {
        loop {
            // read frame with optional idle timeout
            let frame_result = if let Some(timeout) = self.idle_timeout {
                match tokio::time::timeout(timeout, read_frame(reader)).await {
                    Ok(result) => result,
                    Err(_) => {
                        debug!(client = %short_key(&client_key), "DERP connection idle timeout");
                        break;
                    }
                }
            } else {
                read_frame(reader).await
            };

            let (frame_type, payload) = match frame_result {
                Ok(frame) => frame,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(err.into()),
            };

            match frame_type {
                FRAME_SEND_PACKET => self.relay_packet(client_key, payload).await?,
                FRAME_PING => {
                    let _ = outbound
                        .send(ServerFrame {
                            frame_type: FRAME_PONG,
                            payload,
                        })
                        .await;
                }
                FRAME_KEEP_ALIVE => {}
                _ => {}
            }
        }

        Ok(())
    }

    async fn relay_packet(&self, src: [u8; 32], payload: Vec<u8>) -> Result<(), DerpServerError> {
        if payload.len() < 32 {
            return Err(DerpServerError::Protocol(
                "DERP send packet missing destination".into(),
            ));
        }

        let mut dst = [0u8; 32];
        dst.copy_from_slice(&payload[..32]);
        let data = payload[32..].to_vec();

        let target_sender = {
            let guard = self.state.clients.lock().await;
            guard.get(&dst).cloned()
        };

        if let Some(sender) = target_sender {
            let mut frame_payload = Vec::with_capacity(32 + data.len());
            frame_payload.extend_from_slice(&src);
            frame_payload.extend_from_slice(&data);
            let _ = sender
                .send(ServerFrame {
                    frame_type: FRAME_RECV_PACKET,
                    payload: frame_payload,
                })
                .await;
        }

        Ok(())
    }

    async fn send_server_key<W>(&self, writer: &mut BufWriter<W>) -> Result<(), DerpServerError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut payload = Vec::with_capacity(DERP_MAGIC.len() + self.crypto.public_bytes.len());
        payload.extend_from_slice(DERP_MAGIC);
        payload.extend_from_slice(&self.crypto.public_bytes);
        write_frame(writer, FRAME_SERVER_KEY, &payload).await?;
        Ok(())
    }

    async fn receive_client_info<R>(
        &self,
        reader: &mut BufReader<R>,
    ) -> Result<[u8; 32], DerpServerError>
    where
        R: AsyncRead + Unpin,
    {
        let (frame_type, payload) = read_frame(reader).await?;
        if frame_type != FRAME_CLIENT_INFO {
            return Err(DerpServerError::Protocol("expected FrameClientInfo".into()));
        }
        if payload.len() < 56 {
            return Err(DerpServerError::Protocol("short FrameClientInfo".into()));
        }

        let mut client_key = [0u8; 32];
        client_key.copy_from_slice(&payload[..32]);
        let nonce = crypto_box::aead::generic_array::GenericArray::from_slice(&payload[32..56]);
        let boxed = &payload[56..];

        let client_public = PublicKey::from(client_key);
        let cipher = SalsaBox::new(&client_public, &self.crypto.secret);
        let plaintext = cipher
            .decrypt(nonce, boxed)
            .map_err(|_| DerpServerError::Crypto("invalid client info".into()))?;
        serde_json::from_slice::<Value>(&plaintext)
            .map_err(|err| DerpServerError::Protocol(format!("invalid client info json: {err}")))?;

        Ok(client_key)
    }

    async fn send_server_info<W>(
        &self,
        writer: &mut BufWriter<W>,
        client_key: &[u8; 32],
    ) -> Result<(), DerpServerError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let client_public = PublicKey::from(*client_key);
        let cipher = SalsaBox::new(&client_public, &self.crypto.secret);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let plaintext = serde_json::to_vec(&json!({ "Version": DERP_PROTOCOL_VERSION }))
            .map_err(|err| DerpServerError::Protocol(format!("invalid server info json: {err}")))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| DerpServerError::Crypto("failed to encrypt server info".into()))?;

        let mut payload = Vec::with_capacity(24 + ciphertext.len());
        payload.extend_from_slice(nonce.as_slice());
        payload.extend_from_slice(&ciphertext);
        write_frame(writer, FRAME_SERVER_INFO, &payload).await?;
        Ok(())
    }
}

/// options for creating an embedded derp server.
pub struct EmbeddedDerpOptions {
    /// the noise keypair for derp protocol encryption.
    pub keypair: Keypair,
    /// idle timeout for connections in seconds. 0 to disable.
    pub idle_timeout_secs: u64,
}

impl EmbeddedDerpOptions {
    /// set the idle timeout (0 to disable)
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            idle_timeout_secs: railscale_types::DEFAULT_DERP_IDLE_TIMEOUT_SECS,
        }
    }

    /// set the idle timeout (0 to disable).
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }
}

#[derive(Clone)]
struct DerpKeyMaterial {
    secret: SecretKey,
    public_bytes: [u8; 32],
}

impl DerpKeyMaterial {
    fn new(keypair: Keypair) -> Self {
        assert!(
            keypair.private.len() >= 32,
            "DERP keypair private key must be 32 bytes"
        );
        assert!(
            keypair.public.len() >= 32,
            "DERP keypair public key must be 32 bytes"
        );

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&keypair.private[..32]);
        let secret = SecretKey::from(secret_bytes);

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(&keypair.public[..32]);

        Self {
            secret,
            public_bytes,
        }
    }
}

#[derive(Default)]
struct DerpServerState {
    clients: Mutex<HashMap<[u8; 32], mpsc::Sender<ServerFrame>>>,
}

#[derive(Debug, Clone)]
struct ServerFrame {
    frame_type: u8,
    payload: Vec<u8>,
}

/// errors that can occur in the derp server.
#[derive(Debug, Error)]
pub enum DerpServerError {
    /// i/o error during connection handling.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// tls error during connection setup.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    /// cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// derp protocol error (invalid frame, unexpected state).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// derp handshake failed.
    #[error("handshake error: {0}")]
    Handshake(String),
}

async fn read_frame<R>(reader: &mut R) -> io::Result<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    // reject frames larger than max_frame_payload_size to prevent memory exhaustion
    if len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "DERP frame too large: {} bytes (max {})",
                len, MAX_FRAME_PAYLOAD_SIZE
            ),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

async fn write_frame<W>(writer: &mut W, frame_type: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn write_loop<W>(mut writer: BufWriter<W>, mut rx: mpsc::Receiver<ServerFrame>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = rx.recv().await {
        if let Err(err) = write_frame(&mut writer, frame.frame_type, &frame.payload).await {
            if matches!(
                err.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
            ) {
                break;
            }
        }
    }
}

struct PrefixedStream<T> {
    inner: T,
    buffer: Vec<u8>,
    offset: usize,
}

impl<T> PrefixedStream<T> {
    fn new(inner: T, buffer: Vec<u8>) -> Self {
        Self {
            inner,
            buffer,
            offset: 0,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.buffer.len() {
            let remaining = &self.buffer[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn short_key(key: &[u8; 32]) -> String {
    format!("nodekey:{:02x}{:02x}...", key[0], key[1])
}
