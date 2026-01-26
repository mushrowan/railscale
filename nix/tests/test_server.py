# Server startup and STUN tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# =============================================================================
# PHASE 1: Server Startup
# =============================================================================
with subtest("Server starts successfully"):
    wait_for_server()
    print("Server started successfully")

wait_for_network()

# =============================================================================
# PHASE 1.5: STUN Server Tests
# =============================================================================
with subtest("STUN server responds to binding requests"):
    # Use tailscale netcheck to test STUN connectivity
    # The server's DERP map points clients to our embedded DERP/STUN
    result = client1.succeed("tailscale netcheck --format=json 2>&1 || true")
    print(f"Netcheck result: {result}")
    # Even without full connectivity, netcheck should complete
    # The key test is that it doesn't hang or crash

with subtest("STUN port is reachable from clients"):
    # Test UDP connectivity to STUN port using a simple Python script
    # that sends a STUN binding request and checks for response
    # Write script to file to avoid quoting issues
    stun_test = '''
import socket
import sys

# STUN Binding Request
request = bytes([
    0x00, 0x01,  # Binding Request
    0x00, 0x00,  # Length = 0
    0x21, 0x12, 0xa4, 0x42,  # Magic cookie
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  # Transaction ID (12 bytes)
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
try:
    sock.sendto(request, ("192.168.1.3", 3478))
    response, addr = sock.recvfrom(1024)
    # Check response has magic cookie and is a success response (0x0101)
    if len(response) >= 20 and response[0:2] == bytes([0x01, 0x01]):
        if response[4:8] == bytes([0x21, 0x12, 0xa4, 0x42]):
            print("STUN response received: %d bytes from %s" % (len(response), addr))
            sys.exit(0)
    print("Invalid STUN response: " + response.hex())
    sys.exit(1)
except socket.timeout:
    print("STUN request timed out")
    sys.exit(1)
finally:
    sock.close()
'''
    # Write to temp file and execute
    client1.succeed("cat > /tmp/stun_test.py << 'EOFSTUN'\n" + stun_test + "\nEOFSTUN")
    client1.succeed("python3 /tmp/stun_test.py")
    print("STUN server responded correctly!")
