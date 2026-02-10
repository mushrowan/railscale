//! minimal stun server for nat traversal.
//!
//! implements rfc 8489 stun binding request/response, which is all that
//! tailscale clients need for endpoint discovery.
//!
//! # Fallback Strategy
//!
//! if this minimal implementation proves insufficient (e.g., needs fingerprint,
//! message-integrity, or turn extensions), switch to the `stun` crate from
//! webrtc-rs rather than expanding this code.

/// stun magic cookie (rfc 8489).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// stun binding request message type.
const BINDING_REQUEST: u16 = 0x0001;

/// stun binding success response message type.
const BINDING_SUCCESS: u16 = 0x0101;

/// xor-mapped-address attribute type.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// address family: ipv4.
const FAMILY_IPV4: u8 = 0x01;

/// address family: ipv6.
const FAMILY_IPV6: u8 = 0x02;

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// type alias for the per-ip stun rate limiter.
type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// a running stun server handle.
pub struct StunServer {
    /// the address the server is listening on.
    pub local_addr: SocketAddr,
    /// handle to the background task.
    pub handle: JoinHandle<()>,
}

/// configuration for the stun server.
pub struct StunServerConfig {
    /// address to bind to.
    pub listen_addr: SocketAddr,
    /// rate limit per ip (requests per minute). 0 to disable.
    pub rate_per_minute: u32,
}

/// spawn a stun server listening on the given address.
///
/// the server responds to stun binding requests with the client's
/// reflexive transport address (their public IP:port as seen by this server).
///
/// use `0.0.0.0:0` or `127.0.0.1:0` to bind to a random available port,
/// then check `StunServer::local_addr` for the actual bound address.
pub async fn spawn_stun_server(listen_addr: SocketAddr) -> std::io::Result<StunServer> {
    spawn_stun_server_with_config(StunServerConfig {
        listen_addr,
        rate_per_minute: 0, // No rate limiting for backwards compatibility
    })
    .await
}

/// spawn a stun server with custom configuration.
pub async fn spawn_stun_server_with_config(
    config: StunServerConfig,
) -> std::io::Result<StunServer> {
    let socket = UdpSocket::bind(config.listen_addr).await?;
    let local_addr = socket.local_addr()?;

    // create per-ip rate limiter if enabled
    let rate_limiter: Option<Arc<IpRateLimiter>> = if config.rate_per_minute > 0 {
        let quota = Quota::per_minute(NonZeroU32::new(config.rate_per_minute).expect("rate > 0"));
        Some(Arc::new(RateLimiter::keyed(quota)))
    } else {
        None
    };

    info!(
        %local_addr,
        rate_per_minute = config.rate_per_minute,
        "STUN server listening"
    );

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];

        loop {
            let (len, peer_addr) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("STUN recv error: {}", e);
                    continue;
                }
            };

            let packet = &buf[..len];

            if !is_stun_binding_request(packet) {
                debug!("Ignoring non-STUN packet from {}", peer_addr);
                continue;
            }

            // check rate limit per ip
            if let Some(ref limiter) = rate_limiter
                && limiter.check_key(&peer_addr.ip()).is_err()
            {
                debug!("STUN request rate limited from {}", peer_addr);
                continue; // Silently drop - UDP, no response
            }

            let Some(txid) = extract_transaction_id(packet) else {
                debug!("Invalid STUN packet from {}", peer_addr);
                continue;
            };

            let response = build_binding_response(txid, peer_addr);

            if let Err(e) = socket.send_to(&response, peer_addr).await {
                error!("STUN send error to {}: {}", peer_addr, e);
            } else {
                debug!("STUN response sent to {}", peer_addr);
            }
        }
    });

    Ok(StunServer { local_addr, handle })
}

/// extract the 12-byte transaction id from a stun request.
///
/// returns `none` if the packet is too short.
pub fn extract_transaction_id(packet: &[u8]) -> Option<[u8; 12]> {
    if packet.len() < 20 {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&packet[8..20]);
    Some(txid)
}

/// build a stun binding success response with xor-mapped-address.
///
/// the response tells the client their reflexive transport address
/// (their public IP:port as seen by this server).
pub fn build_binding_response(transaction_id: [u8; 12], addr: SocketAddr) -> Vec<u8> {
    let (family, xor_addr_bytes) = match addr {
        SocketAddr::V4(v4) => {
            let ip_bytes = v4.ip().octets();
            let xor_ip: [u8; 4] = [
                ip_bytes[0] ^ MAGIC_COOKIE[0],
                ip_bytes[1] ^ MAGIC_COOKIE[1],
                ip_bytes[2] ^ MAGIC_COOKIE[2],
                ip_bytes[3] ^ MAGIC_COOKIE[3],
            ];
            (FAMILY_IPV4, xor_ip.to_vec())
        }
        SocketAddr::V6(v6) => {
            let ip_bytes = v6.ip().octets();
            // xor key is magic cookie (4 bytes) + transaction id (12 bytes)
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&MAGIC_COOKIE);
            xor_key[4..16].copy_from_slice(&transaction_id);
            let xor_ip: Vec<u8> = ip_bytes.iter().zip(&xor_key).map(|(a, b)| a ^ b).collect();
            (FAMILY_IPV6, xor_ip)
        }
    };

    // xor port with first 2 bytes of magic cookie
    let xor_port = addr.port() ^ 0x2112;

    // attribute value length: 1 (reserved) + 1 (family) + 2 (port) + addr bytes
    let attr_value_len = 4 + xor_addr_bytes.len();
    // message length = attribute header (4) + attribute value
    let msg_len = 4 + attr_value_len;

    let mut response = Vec::with_capacity(20 + msg_len);

    // stun header (20 bytes)
    response.extend_from_slice(&BINDING_SUCCESS.to_be_bytes()); // Message type
    response.extend_from_slice(&(msg_len as u16).to_be_bytes()); // Message length
    response.extend_from_slice(&MAGIC_COOKIE); // Magic cookie
    response.extend_from_slice(&transaction_id); // Transaction ID

    // xor-mapped-address attribute
    response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes()); // Attribute type
    response.extend_from_slice(&(attr_value_len as u16).to_be_bytes()); // Attribute length
    response.push(0x00); // Reserved
    response.push(family); // Address family
    response.extend_from_slice(&xor_port.to_be_bytes()); // XOR'd port
    response.extend_from_slice(&xor_addr_bytes); // XOR'd address

    response
}

/// check if a packet is a stun binding request.
///
/// validates:
/// - length >= 20 bytes (stun header size)
/// - first 2 bits are 0 (stun indicator)
/// - Magic cookie at bytes 4-8
/// - Message type is Binding Request (0x0001)
pub fn is_stun_binding_request(packet: &[u8]) -> bool {
    // stun header is 20 bytes minimum
    if packet.len() < 20 {
        return false;
    }

    // first 2 bits must be 0 (distinguishes stun from rtp/rtcp)
    if packet[0] & 0xC0 != 0 {
        return false;
    }

    // check magic cookie at bytes 4-7
    if packet[4..8] != MAGIC_COOKIE {
        return false;
    }

    // check message type is binding request (0x0001)
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    msg_type == BINDING_REQUEST
}

#[cfg(test)]
mod tests {
    use super::*;

    /// build a valid stun binding request for testing.
    fn make_binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
        let mut packet = vec![
            0x00, 0x01, // Binding Request
            0x00, 0x00, // Message length (no attributes)
            0x21, 0x12, 0xA4, 0x42, // Magic cookie
        ];
        packet.extend_from_slice(&transaction_id);
        packet
    }

    #[test]
    fn test_valid_binding_request() {
        let txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let packet = make_binding_request(txid);
        assert!(is_stun_binding_request(&packet));
    }

    #[test]
    fn test_packet_too_short() {
        let packet = vec![0x00, 0x01, 0x00, 0x00]; // Only 4 bytes
        assert!(!is_stun_binding_request(&packet));
    }

    #[test]
    fn test_wrong_magic_cookie() {
        let mut packet = make_binding_request([0; 12]);
        packet[4] = 0xFF; // Corrupt magic cookie
        assert!(!is_stun_binding_request(&packet));
    }

    #[test]
    fn test_wrong_message_type() {
        let mut packet = make_binding_request([0; 12]);
        packet[0] = 0x01; // Binding Response, not Request
        packet[1] = 0x01;
        assert!(!is_stun_binding_request(&packet));
    }

    #[test]
    fn test_first_two_bits_must_be_zero() {
        let mut packet = make_binding_request([0; 12]);
        packet[0] = 0x80; // Set first bit
        assert!(!is_stun_binding_request(&packet));
    }

    #[test]
    fn test_extract_transaction_id() {
        let txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let packet = make_binding_request(txid);
        assert_eq!(extract_transaction_id(&packet), Some(txid));
    }

    #[test]
    fn test_extract_transaction_id_too_short() {
        let packet = vec![0; 10];
        assert_eq!(extract_transaction_id(&packet), None);
    }

    #[test]
    fn test_build_response_ipv4() {
        let txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let response = build_binding_response(txid, addr);

        // check header
        assert_eq!(response[0..2], [0x01, 0x01]); // Binding Success
        assert_eq!(response[2..4], [0x00, 0x0c]); // Length = 12 (XOR-MAPPED-ADDRESS)
        assert_eq!(response[4..8], MAGIC_COOKIE);
        assert_eq!(response[8..20], txid);

        // check xor-mapped-address attribute
        assert_eq!(response[20..22], [0x00, 0x20]); // Attribute type
        assert_eq!(response[22..24], [0x00, 0x08]); // Attribute length = 8
        assert_eq!(response[24], 0x00); // Reserved
        assert_eq!(response[25], 0x01); // Family: IPv4

        // port 32853 xor'd with 0x2112 = 0x804f xor 0x2112 = 0xa15d
        // actually: 32853 = 0x8055, xor 0x2112 = 0xa147
        let xor_port = 32853u16 ^ 0x2112;
        assert_eq!(response[26..28], xor_port.to_be_bytes());

        // ip 192.0.2.1 xor'd with magic cookie
        // 192.0.2.1 = [0xc0, 0x00, 0x02, 0x01]
        // xor [0x21, 0x12, 0xa4, 0x42] = [0xe1, 0x12, 0xa6, 0x43]
        assert_eq!(response[28..32], [0xe1, 0x12, 0xa6, 0x43]);
    }

    #[test]
    fn test_build_response_ipv6() {
        let txid = [0xAA; 12];
        let addr: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let response = build_binding_response(txid, addr);

        // check header
        assert_eq!(response[0..2], [0x01, 0x01]); // Binding Success
        assert_eq!(response[2..4], [0x00, 0x18]); // Length = 24 (IPv6 XOR-MAPPED-ADDRESS)
        assert_eq!(response[4..8], MAGIC_COOKIE);
        assert_eq!(response[8..20], txid);

        // check xor-mapped-address attribute
        assert_eq!(response[20..22], [0x00, 0x20]); // Attribute type
        assert_eq!(response[22..24], [0x00, 0x14]); // Attribute length = 20
        assert_eq!(response[24], 0x00); // Reserved
        assert_eq!(response[25], 0x02); // Family: IPv6

        // port 1234 xor'd with 0x2112
        let xor_port = 1234u16 ^ 0x2112;
        assert_eq!(response[26..28], xor_port.to_be_bytes());

        // ipv6 is xor'd with magic cookie + transaction id (16 bytes total)
        // 2001:db8::1 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        // xor key = magic_cookie ++ txid = [0x21, 0x12, 0xa4, 0x42, 0xaa, 0xaa, ...]
        let ipv6_bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let mut xor_key = [0u8; 16];
        xor_key[0..4].copy_from_slice(&MAGIC_COOKIE);
        xor_key[4..16].copy_from_slice(&txid);
        let expected: Vec<u8> = ipv6_bytes
            .iter()
            .zip(&xor_key)
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(&response[28..44], expected.as_slice());
    }

    #[tokio::test]
    async fn test_stun_server_responds_to_binding_request() {
        // spawn server on random port
        let server = spawn_stun_server("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // create client socket
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // send binding request
        let txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = make_binding_request(txid);
        client.send_to(&request, server.local_addr).await.unwrap();

        // receive response
        let mut buf = [0u8; 256];
        let (len, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for STUN response")
        .unwrap();

        let response = &buf[..len];

        // verify response header
        assert_eq!(response[0..2], [0x01, 0x01]); // Binding Success
        assert_eq!(response[4..8], MAGIC_COOKIE);
        assert_eq!(response[8..20], txid); // Same transaction ID

        // verify xor-mapped-address contains our client address
        assert_eq!(response[20..22], [0x00, 0x20]); // XOR-MAPPED-ADDRESS type
        assert_eq!(response[25], 0x01); // IPv4

        // decode xor'd port
        let xor_port = u16::from_be_bytes([response[26], response[27]]);
        let port = xor_port ^ 0x2112;
        assert_eq!(port, client_addr.port());

        // decode xor'd ip
        let xor_ip = &response[28..32];
        let ip: [u8; 4] = [
            xor_ip[0] ^ MAGIC_COOKIE[0],
            xor_ip[1] ^ MAGIC_COOKIE[1],
            xor_ip[2] ^ MAGIC_COOKIE[2],
            xor_ip[3] ^ MAGIC_COOKIE[3],
        ];
        assert_eq!(ip, [127, 0, 0, 1]);

        server.handle.abort();
    }
}
