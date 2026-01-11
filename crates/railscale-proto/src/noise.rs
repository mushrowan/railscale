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

/// generate a new curve25519 keypair for noise protocol.
///
/// # Returns
/// a `keypair` containing both private and public keys (32 bytes each).
pub fn generate_keypair() -> crate::Result<Keypair> {
    let params = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params);
    Ok(builder.generate_keypair()?)
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
        let params = NOISE_PATTERN.parse()?;
        let builder = Builder::new(params);
        let state = builder.local_private_key(private_key)?.build_responder()?;
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
        let params = NOISE_PATTERN.parse()?;
        let builder = Builder::new(params);
        let state = builder
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

    /// generate a curve25519 keypair for testing.
    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let keypair = builder.generate_keypair().unwrap();
        (keypair.private, keypair.public)
    }

    #[test]
    fn test_handshake_roundtrip() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        // server as responder
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();

        // client as initiator (needs server's public key for ik pattern)
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let mut client = builder
            .local_private_key(&client_priv)
            .unwrap()
            .remote_public_key(&server_pub)
            .unwrap()
            .build_initiator()
            .unwrap();

        // client sends first message: -> e, es, s, ss
        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        let msg1 = &buf[..len];

        // server reads first message
        let payload1 = server.read_message(msg1).unwrap();
        assert_eq!(payload1.len(), 0); // no payload in first message

        // server sends second message: <- e, ee, se
        let msg2 = server.write_message(&[]).unwrap();

        // client reads second message
        let mut buf = vec![0u8; 65535];
        let len = client.read_message(&msg2, &mut buf).unwrap();
        assert_eq!(len, 0); // no payload in second message

        // both sides should have completed handshake
        assert!(server.is_complete());
        assert!(client.is_handshake_finished());

        // server should have client's static key (machine key)
        assert!(server.remote_static().is_some());
        assert_eq!(server.remote_static().unwrap().len(), 32);
    }

    #[test]
    fn test_transport_encryption() {
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        // complete handshake
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let mut client = builder
            .local_private_key(&client_priv)
            .unwrap()
            .remote_public_key(&server_pub)
            .unwrap()
            .build_initiator()
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        // convert to transport mode
        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // test encryption/decryption: client -> server
        let plaintext = b"hello from client";
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = client_transport.write_message(plaintext, &mut buf).unwrap();
        let ciphertext = &buf[..len];

        let decrypted = server_transport.decrypt(ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // test encryption/decryption: server -> client
        let plaintext = b"hello from server";
        let ciphertext = server_transport.encrypt(plaintext).unwrap();

        let mut buf = vec![0u8; ciphertext.len()];
        let len = client_transport
            .read_message(&ciphertext, &mut buf)
            .unwrap();
        let decrypted = &buf[..len];
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_message() {
        let (server_priv, _) = generate_keypair();
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();

        // try to read invalid message
        let result = server.read_message(b"invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_not_complete() {
        let (server_priv, _) = generate_keypair();
        let server = NoiseHandshake::new_responder(&server_priv).unwrap();

        // handshake not complete initially
        assert!(!server.is_complete());

        // no remote static key yet
        assert!(server.remote_static().is_none());
    }

    #[test]
    fn test_into_transport_before_complete() {
        let (server_priv, _) = generate_keypair();
        let server = NoiseHandshake::new_responder(&server_priv).unwrap();

        // should fail if handshake not complete
        let result = server.into_transport();
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_messages_client_to_server() {
        // this test verifies that multiple messages from client to server
        // decrypt correctly (simulating what happens with HTTP/2 over Noise)
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        // complete handshake
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let mut client = builder
            .local_private_key(&client_priv)
            .unwrap()
            .remote_public_key(&server_pub)
            .unwrap()
            .build_initiator()
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        // convert to transport mode
        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // server sends one message first (simulating http/2 settings)
        let server_msg = b"server settings";
        let server_ct = server_transport.encrypt(server_msg).unwrap();

        // now client sends multiple messages (simulating http/2 preface + headers)
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

        // server decrypts all client messages in order
        let decrypted1 = server_transport.decrypt(client_ct1).unwrap();
        assert_eq!(decrypted1, client_msg1, "First message failed");

        let decrypted2 = server_transport.decrypt(client_ct2).unwrap();
        assert_eq!(decrypted2, client_msg2, "Second message failed");

        let decrypted3 = server_transport.decrypt(client_ct3).unwrap();
        assert_eq!(decrypted3, client_msg3, "Third message failed");

        // client can also decrypt server's message
        let mut server_pt_buf = vec![0u8; server_ct.len()];
        let server_pt_len = client_transport
            .read_message(&server_ct, &mut server_pt_buf)
            .unwrap();
        assert_eq!(&server_pt_buf[..server_pt_len], server_msg);
    }

    #[test]
    fn test_with_prologue() {
        // test with tailscale-style prologue to ensure it doesn't affect transport
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        let prologue = b"Tailscale Control Protocol v131";

        // complete handshake with prologue
        let mut server =
            NoiseHandshake::new_responder_with_prologue(&server_priv, prologue).unwrap();
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let mut client = builder
            .local_private_key(&client_priv)
            .unwrap()
            .remote_public_key(&server_pub)
            .unwrap()
            .prologue(prologue)
            .unwrap()
            .build_initiator()
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        // convert to transport mode
        let mut server_transport = server.into_transport().unwrap();
        let mut client_transport = client.into_transport_mode().unwrap();

        // server encrypts first
        let server_settings = b"server settings";
        let _server_ct = server_transport.encrypt(server_settings).unwrap();

        // client sends multiple messages
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

        // server decrypts both
        let decrypted1 = server_transport.decrypt(&client_ct1).unwrap();
        assert_eq!(decrypted1, client_msg1);

        let decrypted2 = server_transport.decrypt(&client_ct2).unwrap();
        assert_eq!(decrypted2, client_msg2);
    }

    #[test]
    fn test_interleaved_encrypt_decrypt() {
        // test that server can encrypt and decrypt interleaved
        // (since we encrypt SETTINGS while receiving client data)
        let (server_priv, server_pub) = generate_keypair();
        let (client_priv, _) = generate_keypair();

        // complete handshake
        let mut server = NoiseHandshake::new_responder(&server_priv).unwrap();
        let params = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let mut client = builder
            .local_private_key(&client_priv)
            .unwrap()
            .remote_public_key(&server_pub)
            .unwrap()
            .build_initiator()
            .unwrap();

        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len]).unwrap();

        let msg2 = server.write_message(&[]).unwrap();
        let mut buf = vec![0u8; 65535];
        client.read_message(&msg2, &mut buf).unwrap();

        // convert to transport mode
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
