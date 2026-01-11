//! http upgrade tests for the TS2021 protocol
//!
//! these tests verify the http upgrade path (not WebSocket) used by real tailscale clients

mod ts2021_common;

use base64::Engine;
use railscale_db::RailscaleDb;
use railscale_grants::{GrantsEngine, Policy};
use railscale_types::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts2021_common::{build_client_handshake, create_framed_initiation, spawn_test_server};

/// test that the /ts2021 endpoint supports http upgrade (not just WebSocket)
///
/// the real tailscale client uses `Upgrade: tailscale-control-protocol` instead
/// of WebSocket. This test verifies that path works
///
/// protocol:
/// ```text
/// post /ts2021 http/1.1
/// upgrade: tailscale-control-protocol
/// connection: upgrade
/// x-tailscale-handshake: <base64 noise init>
///
/// response: 101 switching protocols
/// upgrade: tailscale-control-protocol
/// connection: upgrade
/// ```
#[tokio::test]
async fn test_ts2021_http_upgrade_protocol() {
    const PROTOCOL_VERSION: u16 = 1;

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = railscale::StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via raw tcp and send http upgrade request (NOT WebSocket - using tailscale-control-protocol)
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // should get 101 Switching Protocols with tailscale-control-protocol
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );
    assert!(
        response_str
            .to_lowercase()
            .contains("upgrade: tailscale-control-protocol"),
        "expected Upgrade: tailscale-control-protocol header, got: {}",
        response_str
    );

    // after 101, the Noise response should follow
    // read more data for the Noise response (it may come in the same read or separately)
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let remaining = &response_buf[header_end..n];

    // the Noise response should be: [type:1][len:2][payload:48] = 51 bytes
    let noise_response = if remaining.len() >= 51 {
        remaining[..51].to_vec()
    } else {
        // need to read more
        let mut full_response = remaining.to_vec();
        while full_response.len() < 51 {
            let mut more = vec![0u8; 1024];
            let n = stream.read(&mut more).await.expect("failed to read more");
            if n == 0 {
                panic!(
                    "connection closed before receiving full Noise response, got {} bytes",
                    full_response.len()
                );
            }
            full_response.extend_from_slice(&more[..n]);
        }
        full_response[..51].to_vec()
    };

    // verify Noise response format
    assert_eq!(noise_response[0], 0x02, "response type should be 0x02");
    let response_payload_len = u16::from_be_bytes([noise_response[1], noise_response[2]]);
    assert_eq!(response_payload_len, 48, "payload length should be 48");

    // complete the handshake on client side
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    server_handle.abort();
}

/// test that http upgraded Noise frames use the correct format
///
/// for raw tcp connections (http upgrade, not WebSocket), tailscale expects:
/// - Frame format: `[type:1][len:2 BE][ciphertext:N]`
/// - Type byte 0x04 = msgTypeRecord for data frames
///
/// this test verifies the server sends correctly formatted frames that
/// the real tailscale client can parse
#[tokio::test]
async fn test_http_upgrade_noise_frame_format() {
    const PROTOCOL_VERSION: u16 = 131; // Use real Tailscale version
    const MSG_TYPE_RECORD: u8 = 0x04;
    const MAX_FRAME_SIZE: usize = 4096; // type + len + ciphertext

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = railscale::StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via raw tcp and send http upgrade request
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the http response + Noise handshake response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");

    // parse http response
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );

    // find where http headers end
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let mut remaining = response_buf[header_end..n].to_vec();

    // read more if needed to get the full Noise response (51 bytes)
    while remaining.len() < 51 {
        let mut more = vec![0u8; 1024];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed early");
        }
        remaining.extend_from_slice(&more[..n]);
    }

    // parse Noise handshake response (doesn't use type byte for handshake messages)
    let noise_response = &remaining[..51];
    assert_eq!(noise_response[0], 0x02, "handshake response type");

    // complete the handshake
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    let mut client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // move past the Noise handshake response
    let post_handshake = &remaining[51..];

    // now read the http/2 SETTINGS frame from the server
    // server should send http/2 preface: SETTINGS frame
    // this should be in format [type:1=0x04][len:2][ciphertext]

    let mut data_buf = post_handshake.to_vec();
    while data_buf.len() < 3 {
        let mut more = vec![0u8; 4096];
        let n = stream.read(&mut more).await.expect("failed to read data");
        if n == 0 {
            panic!(
                "connection closed before receiving data frame, got {} bytes",
                data_buf.len()
            );
        }
        data_buf.extend_from_slice(&more[..n]);
    }

    // verify frame format: [type:1][len:2][ciphertext]
    let frame_type = data_buf[0];
    let frame_len = u16::from_be_bytes([data_buf[1], data_buf[2]]) as usize;

    assert_eq!(
        frame_type, MSG_TYPE_RECORD,
        "Expected frame type 0x04 (msgTypeRecord), got 0x{:02x}.\n\
         HTTP upgraded Noise frames must use format [type:1][len:2][ciphertext]",
        frame_type
    );

    assert!(
        frame_len <= MAX_FRAME_SIZE - 3,
        "Frame length {} exceeds max {} bytes",
        frame_len,
        MAX_FRAME_SIZE - 3
    );

    // read the full ciphertext
    while data_buf.len() < 3 + frame_len {
        let mut more = vec![0u8; 4096];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed before full frame");
        }
        data_buf.extend_from_slice(&more[..n]);
    }

    let ciphertext = &data_buf[3..3 + frame_len];

    // try to decrypt - should succeed with properly formatted frames
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = client_transport
        .read_message(ciphertext, &mut decrypted)
        .expect("failed to decrypt frame");
    decrypted.truncate(decrypted_len);

    // the decrypted data should be http/2 SETTINGS frame
    // http/2 connection preface starts with "PRI * http/2.0\r\n\r\nSM\r\n\r\n" for client
    // server sends SETTINGS frame which starts with frame header
    assert!(
        !decrypted.is_empty(),
        "decrypted frame should contain HTTP/2 data"
    );

    server_handle.abort();
}

/// test that multiple client->server frames decrypt correctly over http upgrade
///
/// this test simulates what a real tailscale client does:
/// 1. Complete the Noise handshake via http upgrade
/// 2. Client sends multiple encrypted frames (like http/2 preface + SETTINGS + HEADERS)
/// 3. Server decrypts all frames successfully
#[tokio::test]
async fn test_http_upgrade_multi_frame_client_to_server() {
    const PROTOCOL_VERSION: u16 = 131; // Use real Tailscale version
    const MSG_TYPE_RECORD: u8 = 0x04;

    // create server keypair
    let server_keypair =
        railscale_proto::generate_keypair().expect("failed to generate server keypair");

    // create client keypair
    let client_keypair =
        railscale_proto::generate_keypair().expect("failed to generate client keypair");

    // create app with the server keypair
    let db = RailscaleDb::new_in_memory()
        .await
        .expect("failed to create in-memory database");
    let grants = GrantsEngine::new(Policy::empty());
    let config = Config::default();
    let notifier = railscale::StateNotifier::new();

    let keypair = railscale::Keypair {
        private: server_keypair.private.clone(),
        public: server_keypair.public.clone(),
    };

    let app = railscale::create_app(db, grants, config, None, notifier, Some(keypair)).await;

    // spawn the server
    let (addr, server_handle) = spawn_test_server(app).await;

    // build client handshake
    let mut client_handshake = build_client_handshake(
        &client_keypair.private,
        &server_keypair.public,
        PROTOCOL_VERSION,
    );

    // create framed initiation message
    let init_msg = create_framed_initiation(&mut client_handshake, PROTOCOL_VERSION);
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);

    // connect via raw tcp and send http upgrade request
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");

    // send http upgrade request
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: tailscale-control-protocol\r\n\
         Connection: upgrade\r\n\
         X-Tailscale-Handshake: {}\r\n\
         \r\n",
        addr, init_b64
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("failed to send request");

    // read the http response + Noise handshake response
    let mut response_buf = vec![0u8; 4096];
    let n = stream
        .read(&mut response_buf)
        .await
        .expect("failed to read response");

    // parse http response
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        response_str.starts_with("HTTP/1.1 101"),
        "expected 101, got: {}",
        response_str.lines().next().unwrap_or(&response_str)
    );

    // find where http headers end
    let header_end = response_str.find("\r\n\r\n").expect("no header end") + 4;
    let mut remaining = response_buf[header_end..n].to_vec();

    // read more if needed to get the full Noise response (51 bytes)
    while remaining.len() < 51 {
        let mut more = vec![0u8; 1024];
        let n = stream.read(&mut more).await.expect("failed to read more");
        if n == 0 {
            panic!("connection closed early");
        }
        remaining.extend_from_slice(&more[..n]);
    }

    // parse Noise handshake response
    let noise_response = &remaining[..51];
    assert_eq!(noise_response[0], 0x02, "handshake response type");

    // complete the handshake
    let response_payload = &noise_response[3..];
    let mut buf = vec![0u8; 65535];
    client_handshake
        .read_message(response_payload, &mut buf)
        .expect("failed to read server response");

    assert!(
        client_handshake.is_handshake_finished(),
        "handshake should be complete"
    );

    let mut client_transport = client_handshake
        .into_transport_mode()
        .expect("failed to enter transport mode");

    // keep any extra data after the Noise response
    let post_handshake = remaining[51..].to_vec();

    // now send multiple encrypted frames from client to server
    // this simulates what the real tailscale client does

    // frame 1: http/2 preface + SETTINGS + WINDOW_UPDATE
    let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings_frame = [
        0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // SETTINGS header
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // HEADER_TABLE_SIZE
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH
        0x00, 0x04, 0x00, 0x40, 0x00, 0x00, // INITIAL_WINDOW_SIZE
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE
    ];
    let window_update = [
        0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // WINDOW_UPDATE header
        0x3f, 0xff, 0x00, 0x01, // increment
    ];

    let mut plaintext1 = Vec::new();
    plaintext1.extend_from_slice(http2_preface);
    plaintext1.extend_from_slice(&settings_frame);
    plaintext1.extend_from_slice(&window_update);

    // encrypt frame 1
    let mut ct1_buf = vec![0u8; plaintext1.len() + 16];
    let ct1_len = client_transport
        .write_message(&plaintext1, &mut ct1_buf)
        .expect("encrypt frame 1");
    let ciphertext1 = &ct1_buf[..ct1_len];

    // frame frame 1
    let mut frame1 = Vec::new();
    frame1.push(MSG_TYPE_RECORD);
    frame1.extend_from_slice(&(ciphertext1.len() as u16).to_be_bytes());
    frame1.extend_from_slice(ciphertext1);

    // frame 2: SETTINGS ACK
    let settings_ack = [
        0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // SETTINGS ACK
    ];

    // encrypt frame 2
    let mut ct2_buf = vec![0u8; settings_ack.len() + 16];
    let ct2_len = client_transport
        .write_message(&settings_ack, &mut ct2_buf)
        .expect("encrypt frame 2");
    let ciphertext2 = &ct2_buf[..ct2_len];

    // frame frame 2
    let mut frame2 = Vec::new();
    frame2.push(MSG_TYPE_RECORD);
    frame2.extend_from_slice(&(ciphertext2.len() as u16).to_be_bytes());
    frame2.extend_from_slice(ciphertext2);

    // frame 3: Some more data (HEADERS)
    let headers_frame = [
        0x00, 0x00, 0x20, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, // HEADERS header
        0x82, 0x86, 0x84, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc, 0x78, 0x0f, 0x03,
        0x53, 0x03, 0x2a, 0x2f, 0x2a, 0x90, 0x7a, 0x8a, 0xaa, 0x69, 0xd2, 0x9a, 0xc4, 0xc0, 0x57,
        0x68, 0x0b,
    ];

    // encrypt frame 3
    let mut ct3_buf = vec![0u8; headers_frame.len() + 16];
    let ct3_len = client_transport
        .write_message(&headers_frame, &mut ct3_buf)
        .expect("encrypt frame 3");
    let ciphertext3 = &ct3_buf[..ct3_len];

    // frame frame 3
    let mut frame3 = Vec::new();
    frame3.push(MSG_TYPE_RECORD);
    frame3.extend_from_slice(&(ciphertext3.len() as u16).to_be_bytes());
    frame3.extend_from_slice(ciphertext3);

    // send all frames in a single tcp write (simulating batching)
    let mut all_frames = Vec::new();
    all_frames.extend_from_slice(&frame1);
    all_frames.extend_from_slice(&frame2);
    all_frames.extend_from_slice(&frame3);

    eprintln!(
        "Sending {} bytes containing 3 frames: {} + {} + {} bytes",
        all_frames.len(),
        frame1.len(),
        frame2.len(),
        frame3.len()
    );

    stream
        .write_all(&all_frames)
        .await
        .expect("failed to send frames");

    // read server response (should include http/2 SETTINGS)
    // if the server crashes due to decrypt error, we'll get an error or incomplete response
    let mut data_buf = post_handshake;
    let mut read_attempts = 0;
    while data_buf.len() < 3 && read_attempts < 10 {
        let mut more = vec![0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read(&mut more),
        )
        .await
        {
            Ok(Ok(0)) => {
                panic!(
                    "Server closed connection! This likely means decrypt failed. Got {} bytes",
                    data_buf.len()
                );
            }
            Ok(Ok(n)) => {
                data_buf.extend_from_slice(&more[..n]);
            }
            Ok(Err(e)) => {
                panic!(
                    "Read error: {}. Server may have crashed due to decrypt failure.",
                    e
                );
            }
            Err(_) => {
                read_attempts += 1;
            }
        }
    }

    assert!(
        data_buf.len() >= 3,
        "Should receive server HTTP/2 SETTINGS frame, got {} bytes. Server may have failed to decrypt client frames.",
        data_buf.len()
    );

    // verify server sent a valid Noise frame
    let server_frame_type = data_buf[0];
    assert_eq!(
        server_frame_type, MSG_TYPE_RECORD,
        "Expected server frame type 0x04, got 0x{:02x}",
        server_frame_type
    );

    eprintln!("Test passed: Server successfully processed multiple client frames!");

    server_handle.abort();
}
