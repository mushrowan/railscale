//! noise protocol implementation for secure communication.
//!
//! tailscale uses the noise protocol for secure communication between
//! clients and the control server.
//!
//! this implementation uses the noise_ik_25519_chachapoly_blake2s pattern:
//! - IK: Initiator knows responder's static public key
//! - 25519: Curve25519 for key exchange
//! - ChaChaPoly: ChaCha20-Poly1305 for encryption
//! - BLAKE2s: Hash function

use snow::{Builder, HandshakeState, Keypair, TransportState};

/// noise protocol pattern used by tailscale.
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// chacha20-poly1305 cipher with big-endian nonce encoding
///
/// tailscale's noise implementation (in go) uses big-endian nonces,
/// while the noise spec / upstream snow uses little-endian. nonce=0
/// is identical in both encodings, so the first message works either
/// way — but all subsequent messages fail with LE nonces
#[derive(Default)]
pub(crate) struct TailscaleChaChaPoly {
    key: [u8; 32],
}

impl snow::types::Cipher for TailscaleChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; 32]) {
        self.key = *key;
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());

        out[..plaintext.len()].copy_from_slice(plaintext);

        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[..plaintext.len()])
            .unwrap();

        out[plaintext.len()..plaintext.len() + 16].copy_from_slice(&tag);
        plaintext.len() + 16
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());

        let message_len = ciphertext.len() - 16;
        out[..message_len].copy_from_slice(&ciphertext[..message_len]);

        ChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(
                &nonce_bytes.into(),
                authtext,
                &mut out[..message_len],
                ciphertext[message_len..].into(),
            )
            .map_err(|_| snow::Error::Decrypt)?;

        Ok(message_len)
    }
}

/// crypto resolver that uses BE nonces for tailscale compatibility
///
/// delegates everything to `DefaultResolver` except ChaChaPoly,
/// which uses `TailscaleChaChaPoly` with big-endian nonce encoding
struct TailscaleResolver;

impl snow::resolvers::CryptoResolver for TailscaleResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        snow::resolvers::DefaultResolver.resolve_rng()
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        snow::resolvers::DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(
        &self,
        choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        snow::resolvers::DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(
        &self,
        choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        match choice {
            snow::params::CipherChoice::ChaChaPoly => {
                Some(Box::new(TailscaleChaChaPoly::default()))
            }
            other => snow::resolvers::DefaultResolver.resolve_cipher(other),
        }
    }
}

/// create a snow Builder with the tailscale-compatible crypto resolver
pub fn builder() -> crate::Result<snow::Builder<'static>> {
    let params = NOISE_PATTERN.parse()?;
    Ok(Builder::with_resolver(params, Box::new(TailscaleResolver)))
}

/// generate a new curve25519 keypair for noise protocol.
///
/// # Returns
/// a `keypair` containing both private and public keys (32 bytes each).
pub fn generate_keypair() -> crate::Result<Keypair> {
    Ok(builder()?.generate_keypair()?)
}

/// noise protocol handshake state.
#[derive(Debug)]
pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    /// create a new handshake as the responder (server).
    ///
    /// # Arguments
    /// * `private_key` - Server's static private key (32 bytes)
    pub fn new_responder(private_key: &[u8]) -> crate::Result<Self> {
        let state = builder()?
            .local_private_key(private_key)?
            .build_responder()?;
        Ok(Self { state })
    }

    /// create a new handshake as the responder (server) with a prologue.
    ///
    /// the prologue is mixed into the handshake hash before any pattern
    /// operations, binding the handshake to the protocol context.
    ///
    /// # Arguments
    /// * `private_key` - Server's static private key (32 bytes)
    /// * `prologue` - Protocol-specific prologue data
    pub fn new_responder_with_prologue(private_key: &[u8], prologue: &[u8]) -> crate::Result<Self> {
        let state = builder()?
            .local_private_key(private_key)?
            .prologue(prologue)?
            .build_responder()?;
        Ok(Self { state })
    }

    /// process an incoming handshake message.
    ///
    /// # Arguments
    /// * `message` - The incoming handshake message from the client
    ///
    /// # Returns
    /// the payload extracted from the message (if any).
    pub fn read_message(&mut self, message: &[u8]) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// generate an outgoing handshake message.
    ///
    /// # Arguments
    /// * `payload` - Optional payload to include in the handshake message
    ///
    /// # Returns
    /// the handshake message to send to the client.
    pub fn write_message(&mut self, payload: &[u8]) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// check if the handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// get the remote static public key after handshake completion.
    ///
    /// this returns the client's machine key (their static public key).
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(|s| s.to_vec())
    }

    /// convert to a transport state for encrypted communication.
    ///
    /// this should be called after the handshake is complete.
    pub fn into_transport(self) -> crate::Result<NoiseTransport> {
        let state = self.state.into_transport_mode()?;
        Ok(NoiseTransport { state })
    }
}

/// noise protocol transport for encrypted communication.
#[derive(Debug)]
pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    /// encrypt a message.
    ///
    /// # Arguments
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    /// the encrypted message (ciphertext + authentication tag).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // 16 bytes for AEAD tag
        let len = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// decrypt a message.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message to decrypt
    ///
    /// # Returns
    /// the decrypted plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// generate a curve25519 keypair for testing
    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let keypair = super::builder().unwrap().generate_keypair().unwrap();
        (keypair.private, keypair.public)
    }

    /// build a client (initiator) using the tailscale resolver
    fn build_initiator(client_priv: &[u8], server_pub: &[u8]) -> snow::HandshakeState {
        super::builder()
            .unwrap()
            .local_private_key(client_priv)
            .unwrap()
            .remote_public_key(server_pub)
            .unwrap()
            .build_initiator()
            .unwrap()
    }

    /// build a client (initiator) with prologue using the tailscale resolver
    fn build_initiator_with_prologue(
        client_priv: &[u8],
        server_pub: &[u8],
        prologue: &[u8],
    ) -> snow::HandshakeState {
        super::builder()
            .unwrap()
            .local_private_key(client_priv)
            .unwrap()
            .remote_public_key(server_pub)
            .unwrap()
            .prologue(prologue)
            .unwrap()
            .build_initiator()
            .unwrap()
    }

    #[test]
    fn test_handshake_roundtrip() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let mut client = build_initiator(&client_priv, &server_pub);

        // client sends first message: -> e, es, s, ss
        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        let msg1 = &buf[..len];

        // server reads first message
        let payload1 = server.read_message(msg1).unwrap();
        assert_eq!(payload1.len(), 0);

        // server sends second message: <- e, ee, se
        let msg2 = server.write_message(&[]).unwrap();

        // client reads second message
        let mut buf = vec![0u8; 65535];
        let len = client.read_message(&msg2, &mut buf).unwrap();
        assert_eq!(len, 0);

        assert!(server.is_complete());
        assert!(client.is_handshake_finished());
        assert!(server.remote_static().is_some());
        assert_eq!(server.remote_static().unwrap().len(), 32);
    }

    #[test]
    fn test_transport_encryption() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let mut client = build_initiator(&client_priv, &server_pub);

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // client -> server
        let plaintext = b"hello from client";
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = client_transport.write_message(plaintext, &mut buf).unwrap();
        let decrypted = server_transport.decrypt(&buf[..len]).unwrap();
        assert_eq!(decrypted, plaintext);

        // server -> client
        let plaintext = b"hello from server";
        let ciphertext = server_transport.encrypt(plaintext).unwrap();
        let mut buf = vec![0u8; ciphertext.len()];
        let len = client_transport
            .read_message(&ciphertext, &mut buf)
            .unwrap();
        assert_eq!(&buf[..len], plaintext);
    }

    #[test]
    fn test_invalid_message() {
        let (server_priv, _) = generate_keypair();
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        assert!(server.read_message(b"invalid").is_err());
    }

    #[test]
    fn test_handshake_not_complete() {
        let (server_priv, _) = generate_keypair();
        let server = NoiseHandshake::new_responder(&server_priv).unwrap();
        assert!(!server.is_complete());
        assert!(server.remote_static().is_none());
    }

    #[test]
    fn test_into_transport_before_complete() {
        let (server_priv, _) = generate_keypair();
        let server = NoiseHandshake::new_responder(&server_priv).unwrap();
        assert!(server.into_transport().is_err());
    }

    #[test]
    fn test_multiple_messages_client_to_server() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let mut client = build_initiator(&client_priv, &server_pub);

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // server sends one message first
        let server_msg = b"server settings";
        let server_ct = server_transport.encrypt(server_msg).unwrap();

        // client sends multiple messages
        let client_msg1 = b"client message 1 - this is the HTTP/2 preface";
        let mut ct1_buf = vec![0u8; client_msg1.len() + 16];
        let ct1_len = client_transport
            .write_message(client_msg1, &mut ct1_buf)
            .unwrap();
        let client_ct1 = &ct1_buf[..ct1_len];

        let client_msg2 = b"client message 2 - this is the HEADERS frame";
        let mut ct2_buf = vec![0u8; client_msg2.len() + 16];
        let ct2_len = client_transport
            .write_message(client_msg2, &mut ct2_buf)
            .unwrap();
        let client_ct2 = &ct2_buf[..ct2_len];

        let client_msg3 = b"client message 3 - more data";
        let mut ct3_buf = vec![0u8; client_msg3.len() + 16];
        let ct3_len = client_transport
            .write_message(client_msg3, &mut ct3_buf)
            .unwrap();
        let client_ct3 = &ct3_buf[..ct3_len];

        let decrypted1 = server_transport.decrypt(client_ct1).unwrap();
        assert_eq!(decrypted1, client_msg1, "First message failed");

        let decrypted2 = server_transport.decrypt(client_ct2).unwrap();
        assert_eq!(decrypted2, client_msg2, "Second message failed");

        let decrypted3 = server_transport.decrypt(client_ct3).unwrap();
        assert_eq!(decrypted3, client_msg3, "Third message failed");

        let mut server_pt_buf = vec![0u8; server_ct.len()];
        let server_pt_len = client_transport
            .read_message(&server_ct, &mut server_pt_buf)
            .unwrap();
        assert_eq!(&server_pt_buf[..server_pt_len], server_msg);
    }

    #[test]
    fn test_with_prologue() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let prologue = b"Tailscale Control Protocol v131";

        let mut server =
            NoiseHandshake::new_responder_with_prologue(&server_priv, prologue).unwrap();
        let mut client = build_initiator_with_prologue(&client_priv, &server_pub, prologue);

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        let server_settings = b"server settings";
        let _server_ct = server_transport.encrypt(server_settings).unwrap();

        let client_msg1 = b"client preface and settings";
        let mut ct1_buf = vec![0u8; client_msg1.len() + 16];
        let ct1_len = client_transport
            .write_message(client_msg1, &mut ct1_buf)
            .unwrap();
        let client_ct1 = ct1_buf[..ct1_len].to_vec();

        let client_msg2 = b"client headers for request";
        let mut ct2_buf = vec![0u8; client_msg2.len() + 16];
        let ct2_len = client_transport
            .write_message(client_msg2, &mut ct2_buf)
            .unwrap();
        let client_ct2 = ct2_buf[..ct2_len].to_vec();

        let decrypted1 = server_transport.decrypt(&client_ct1).unwrap();
        assert_eq!(decrypted1, client_msg1);

        let decrypted2 = server_transport.decrypt(&client_ct2).unwrap();
        assert_eq!(decrypted2, client_msg2);
    }

    /// verify that our custom resolver uses big-endian nonce encoding
    /// (required for tailscale compatibility). with LE nonces, nonce=1
    /// would be [0,0,0,0, 1,0,0,0,0,0,0,0] but with BE it's
    /// [0,0,0,0, 0,0,0,0,0,0,0,1] — producing different ciphertext
    /// after the first message (nonce=0 is identical in both encodings)
    #[test]
    fn test_tailscale_resolver_uses_be_nonces() {
        use snow::types::Cipher;

        let mut cipher = super::TailscaleChaChaPoly::default();
        let key = [0x42u8; 32];
        cipher.set(&key);

        let plaintext = b"hello tailscale";
        let mut ct_be = vec![0u8; plaintext.len() + 16];

        // nonce=1 is where BE vs LE divergence starts
        cipher.encrypt(1, &[], plaintext, &mut ct_be);

        // encrypt same plaintext with LE nonce encoding (upstream default)
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
        let mut nonce_le = [0u8; 12];
        nonce_le[4..].copy_from_slice(&1u64.to_le_bytes());
        let mut ct_le = plaintext.to_vec();
        let tag = ChaCha20Poly1305::new(&key.into())
            .encrypt_in_place_detached(&nonce_le.into(), &[], &mut ct_le)
            .unwrap();
        ct_le.extend_from_slice(&tag);

        // BE and LE ciphertext must differ at nonce > 0
        assert_ne!(
            ct_be[..plaintext.len() + 16],
            ct_le[..],
            "BE and LE nonce encoding should produce different ciphertext at nonce=1"
        );
    }

    #[test]
    fn test_interleaved_encrypt_decrypt() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let mut client = build_initiator(&client_priv, &server_pub);

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // client prepares multiple messages before server sends anything
        let client_msg1 = b"client preface";
        let mut ct1_buf = vec![0u8; client_msg1.len() + 16];
        let ct1_len = client_transport
            .write_message(client_msg1, &mut ct1_buf)
            .unwrap();
        let client_ct1 = ct1_buf[..ct1_len].to_vec();

        let client_msg2 = b"client headers";
        let mut ct2_buf = vec![0u8; client_msg2.len() + 16];
        let ct2_len = client_transport
            .write_message(client_msg2, &mut ct2_buf)
            .unwrap();
        let client_ct2 = ct2_buf[..ct2_len].to_vec();

        // server encrypts its settings first
        let server_settings = b"server settings frame";
        let _server_ct = server_transport.encrypt(server_settings).unwrap();

        // server decrypts client messages (should work even after encrypting)
        let decrypted1 = server_transport.decrypt(&client_ct1).unwrap();
        assert_eq!(
            decrypted1, client_msg1,
            "First message failed after server encrypt"
        );

        let decrypted2 = server_transport.decrypt(&client_ct2).unwrap();
        assert_eq!(
            decrypted2, client_msg2,
            "Second message failed after server encrypt"
        );
    }
}
