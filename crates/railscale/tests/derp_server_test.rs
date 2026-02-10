use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore, OsRng},
};

use railscale::derp_server::{EmbeddedDerpOptions, EmbeddedDerpServer};
use railscale_proto::generate_keypair;
use tokio::io::{
    self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};

use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const DERP_MAGIC: &[u8; 8] = b"DERP\xF0\x9F\x94\x91";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_embedded_derp_relays_packets_between_clients() -> Result<()> {
    let derp_keypair = generate_keypair().context("failed to generate DERP keypair")?;
    let mut server_public = [0u8; 32];
    server_public.copy_from_slice(&derp_keypair.public);

    let server = Arc::new(EmbeddedDerpServer::new(EmbeddedDerpOptions::new(
        derp_keypair,
    )));

    let (client1_stream, server1_stream) = io::duplex(64 * 1024);
    let (client2_stream, server2_stream) = io::duplex(64 * 1024);

    let server_a = server.clone();
    let server_b = server.clone();
    tokio::spawn(async move {
        let _ = server_a.handle_connection(server1_stream, None).await;
    });
    tokio::spawn(async move {
        let _ = server_b.handle_connection(server2_stream, None).await;
    });

    let mut client1 = TestDerpClient::new("client1");
    let mut client2 = TestDerpClient::new("client2");

    client1
        .connect(client1_stream, server_public)
        .await
        .context("client1 failed to connect")?;
    client2
        .connect(client2_stream, server_public)
        .await
        .context("client2 failed to connect")?;

    let payload = b"hello-derp".to_vec();
    client1
        .send_packet(client2.public_key_bytes(), payload.clone())
        .await
        .context("failed to send derp packet")?;

    let received = client2
        .expect_packet(Duration::from_secs(1))
        .await
        .context("client2 failed to receive derp packet")?;

    assert_eq!(received.src, client1.public_key_bytes());
    assert_eq!(received.payload, payload);

    client1.shutdown().await;
    client2.shutdown().await;

    Ok(())
}

struct TestDerpClient {
    name: &'static str,
    secret: SecretKey,
    public: PublicKey,
    writer: Option<Arc<Mutex<WriteHalf<DuplexStream>>>>,
    reader_task: Option<tokio::task::JoinHandle<()>>,
    inbox: mpsc::Receiver<DerpPacket>,
}

impl TestDerpClient {
    fn new(name: &'static str) -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        let (_tx, rx) = mpsc::channel(16);
        Self {
            name,
            secret,
            public,
            writer: None,
            reader_task: None,
            inbox: rx,
        }
    }

    async fn connect(&mut self, stream: DuplexStream, server_public: [u8; 32]) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        self.perform_handshake(&mut reader, &mut writer, server_public)
            .await?;

        let writer = Arc::new(Mutex::new(writer));
        let reader_writer = writer.clone();
        let (tx, rx) = mpsc::channel(16);
        self.inbox = rx;

        let name = self.name;
        let reader_task = tokio::spawn(async move {
            let _ = Self::reader_loop(name, reader, reader_writer, tx).await;
        });

        self.reader_task = Some(reader_task);
        self.writer = Some(writer);
        Ok(())
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    async fn send_packet(&self, dst: [u8; 32], data: Vec<u8>) -> Result<()> {
        let writer = self.writer.as_ref().expect("client not connected").clone();
        let mut writer = writer.lock().await;

        let mut payload = Vec::with_capacity(32 + data.len());
        payload.extend_from_slice(&dst);
        payload.extend_from_slice(&data);
        write_frame(&mut *writer, FRAME_SEND_PACKET, &payload).await?;
        Ok(())
    }

    async fn expect_packet(&mut self, timeout_dur: Duration) -> Result<DerpPacket> {
        let packet = timeout(timeout_dur, self.inbox.recv())
            .await
            .context("timeout waiting for DERP packet")?
            .context("DERP channel closed")?;
        Ok(packet)
    }

    async fn shutdown(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
    }

    async fn perform_handshake(
        &self,
        reader: &mut ReadHalf<DuplexStream>,
        writer: &mut WriteHalf<DuplexStream>,
        server_public: [u8; 32],
    ) -> Result<()> {
        let (frame_type, payload): (u8, Vec<u8>) = read_frame(reader).await?;
        assert_eq!(frame_type, FRAME_SERVER_KEY, "server key frame expected");
        assert_eq!(payload.len(), 40);
        assert_eq!(&payload[..8], DERP_MAGIC);
        assert_eq!(&payload[8..40], &server_public);

        let server_public = PublicKey::from(server_public);
        let cipher = SalsaBox::new(&server_public, &self.secret);

        let client_info = serde_json::json!({ "Version": 2, "IsProber": false });
        let plaintext = serde_json::to_vec(&client_info)?;
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("failed to encrypt client info"))?;

        let mut frame_payload = Vec::with_capacity(32 + 24 + ciphertext.len());
        frame_payload.extend_from_slice(self.public.as_bytes());
        frame_payload.extend_from_slice(nonce.as_slice());
        frame_payload.extend_from_slice(&ciphertext);
        write_frame(writer, FRAME_CLIENT_INFO, &frame_payload).await?;

        let (frame_type, payload): (u8, Vec<u8>) = read_frame(reader).await?;
        assert_eq!(frame_type, FRAME_SERVER_INFO);
        let nonce = crypto_box::aead::generic_array::GenericArray::from_slice(&payload[..24]);
        let boxed = &payload[24..];
        let _ = cipher
            .decrypt(nonce, boxed)
            .map_err(|_| anyhow!("failed to decrypt server info"))?;
        Ok(())
    }

    async fn reader_loop(
        name: &'static str,
        mut reader: ReadHalf<DuplexStream>,
        writer: Arc<Mutex<WriteHalf<DuplexStream>>>,
        sender: mpsc::Sender<DerpPacket>,
    ) -> Result<()> {
        loop {
            let (frame_type, payload): (u8, Vec<u8>) = read_frame(&mut reader).await?;
            match frame_type {
                FRAME_RECV_PACKET => {
                    if payload.len() < 32 {
                        continue;
                    }
                    let mut src = [0u8; 32];
                    src.copy_from_slice(&payload[..32]);
                    let data = payload[32..].to_vec();
                    if sender
                        .send(DerpPacket { src, payload: data })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                FRAME_KEEP_ALIVE => {
                    // ignore
                }
                FRAME_PING => {
                    let mut guard = writer.lock().await;
                    write_frame(&mut *guard, FRAME_PONG, &payload).await?;
                }
                other => {
                    eprintln!("{name}: ignoring frame type {other:#x}");
                }
            }
        }
        Ok(())
    }
}

struct DerpPacket {
    pub src: [u8; 32],
    pub payload: Vec<u8>,
}

async fn read_frame<R>(reader: &mut R) -> Result<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin + Send,
{
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

async fn write_frame<W>(writer: &mut W, frame_type: u8, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let mut header = [0u8; 5];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
