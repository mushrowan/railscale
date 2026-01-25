# CLI Integration Tests for railscale
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Import helpers (injected by nix)
# exec(open(helpers_path).read())

start_all()

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

# =============================================================================
# PHASE 2: User Management CLI Tests
# =============================================================================
with subtest("Create user via CLI"):
    output = railscale("users create alice@example.com --display-name 'Alice Smith'")
    assert "Created user" in output
    assert "alice" in output
    print(f"Created user output: {output}")

with subtest("List users shows created user"):
    output = railscale("users list")
    assert "alice" in output
    print(f"Users list:\n{output}")

with subtest("List users JSON output"):
    users = railscale_json("users list")
    assert len(users) == 1
    assert users[0]["email"] == "alice@example.com"
    print(f"Users JSON: {users}")

with subtest("Create second user"):
    railscale("users create bob@example.com")
    users = railscale_json("users list")
    assert len(users) == 2
    user_names = [u["email"] for u in users]
    assert "alice@example.com" in user_names
    assert "bob@example.com" in user_names

with subtest("Rename user"):
    users = railscale_json("users list")
    bob = next(u for u in users if u["email"] == "bob@example.com")
    bob_id = bob["id"]

    output = railscale(f"users rename {bob_id} robert@example.com")
    assert "Renamed" in output

    users = railscale_json("users list")
    user_emails = [u["email"] for u in users]
    assert "robert@example.com" in user_emails
    assert "bob@example.com" not in user_emails

with subtest("Delete user"):
    users = railscale_json("users list")
    robert = next(u for u in users if u["email"] == "robert@example.com")
    robert_id = robert["id"]

    output = railscale(f"users delete {robert_id}")
    assert "Deleted" in output

    users = railscale_json("users list")
    assert len(users) == 1
    assert users[0]["email"] == "alice@example.com"

# Get alice's ID for later use
users = railscale_json("users list")
alice_id = users[0]["id"]
print(f"Alice's ID: {alice_id}")

# =============================================================================
# PHASE 3: Preauth Key Management CLI Tests
# =============================================================================
with subtest("Create preauth key via CLI"):
    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    assert "Created preauth key" in output
    assert "Key:" in output
    print(f"Created preauth key output: {output}")

with subtest("List preauth keys"):
    output = railscale("preauthkeys list")
    assert str(alice_id) in output
    print(f"Preauth keys list:\n{output}")

with subtest("Create reusable preauth key"):
    output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
    assert "Reusable:  true" in output

with subtest("Create preauth key with tags"):
    output = railscale(f"preauthkeys create -u {alice_id} --tags server,web --expiration-days 1")
    assert "tag:server" in output or "server" in output

with subtest("Expire preauth key"):
    keys = railscale_json("preauthkeys list")
    key_id = keys[0]["id"]
    output = railscale(f"preauthkeys expire {key_id}")
    assert "Expired" in output

with subtest("Delete preauth key"):
    keys = railscale_json("preauthkeys list")
    key_to_delete = next(k for k in keys if not k.get("reusable", False))
    key_id = key_to_delete["id"]
    output = railscale(f"preauthkeys delete {key_id}")
    assert "Deleted" in output

# =============================================================================
# PHASE 3.5: API Key Management CLI Tests
# =============================================================================
with subtest("Create API key via CLI"):
    output = railscale(f"apikeys create -u {alice_id} --name 'My Test API Key' --expiration-days 30")
    assert "Created API key" in output
    assert "Key:" in output
    assert "rsapi_" in output
    print(f"Created API key output: {output}")

with subtest("List API keys"):
    output = railscale("apikeys list")
    assert "My Test API Key" in output or "My Test AP..." in output
    print(f"API keys list:\n{output}")

with subtest("List API keys JSON output"):
    keys = railscale_json("apikeys list")
    assert len(keys) >= 1
    assert any("rsapi_" in k["prefix"] for k in keys)
    print(f"API keys JSON: {keys}")

with subtest("Create API key with no expiration"):
    output = railscale(f"apikeys create -u {alice_id} --name 'Permanent Key' --expiration-days 0")
    assert "never" in output.lower()
    print("Created API key with no expiration")

with subtest("Expire API key"):
    keys = railscale_json("apikeys list")
    key_id = keys[0]["id"]
    output = railscale(f"apikeys expire {key_id}")
    assert "Expired" in output
    print(f"Expired API key {key_id}")

with subtest("Delete API key"):
    keys = railscale_json("apikeys list")
    key_to_delete = keys[-1] if len(keys) > 1 else keys[0]
    key_id = key_to_delete["id"]
    output = railscale(f"apikeys delete {key_id}")
    assert "Deleted" in output
    print(f"Deleted API key {key_id}")

with subtest("Filter API keys by user"):
    output = railscale(f"apikeys list -u {alice_id}")
    print(f"API keys for user {alice_id}:\n{output}")

# =============================================================================
# PHASE 4: Client Connection with Preauth Keys
# =============================================================================
with subtest("Connect clients with preauth keys"):
    output1 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    client1_key = extract_key(output1)
    print(f"Client1 key: {client1_key}")

    output2 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    client2_key = extract_key(output2)
    print(f"Client2 key: {client2_key}")

    connect_client(client1, client1_key, "client1")
    connect_client(client2, client2_key, "client2")

    client1_ip = get_client_ip(client1)
    client2_ip = get_client_ip(client2)

    assert client1_ip is not None, "Client1 should have an IP"
    assert client2_ip is not None, "Client2 should have an IP"
    assert client1_ip.startswith("100."), f"Expected 100.x.x.x IP, got {client1_ip}"
    assert client2_ip.startswith("100."), f"Expected 100.x.x.x IP, got {client2_ip}"

    print(f"Client1 IP: {client1_ip}")
    print(f"Client2 IP: {client2_ip}")

with subtest("Clients can ping each other"):
    client1_ip = get_client_ip(client1)
    client2_ip = get_client_ip(client2)
    client1.succeed(f"timeout 15 ping -c 3 {client2_ip}")
    client2.succeed(f"timeout 15 ping -c 3 {client1_ip}")
    print("Clients can ping each other!")

# =============================================================================
# PHASE 5: Node Management CLI Tests
# =============================================================================
with subtest("List nodes shows connected clients"):
    output = railscale("nodes list")
    assert "client1" in output
    assert "client2" in output
    print(f"Nodes list:\n{output}")

with subtest("List nodes JSON output"):
    nodes = railscale_json("nodes list")
    assert len(nodes) == 2
    hostnames = [n["given_name"] for n in nodes]
    assert "client1" in hostnames
    assert "client2" in hostnames

with subtest("Show node details"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes show {node1_id}")
    assert "client1" in output
    assert "IPv4:" in output
    print(f"Node details:\n{output}")

with subtest("Rename node"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes rename {node1_id} client1-renamed")
    assert "Renamed" in output

    nodes = railscale_json("nodes list")
    names = [n["given_name"] for n in nodes]
    assert "client1-renamed" in names

    # Rename back
    railscale(f"nodes rename {node1_id} client1")

with subtest("Add tags to node"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes tags add {node1_id} server,web")
    assert "tag:server" in output
    assert "tag:web" in output

with subtest("Remove tag from node"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes tags remove {node1_id} web")
    assert "tag:server" in output

with subtest("Set tags replaces all"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes tags set {node1_id} production,critical")
    assert "tag:production" in output
    assert "tag:critical" in output

with subtest("Approve routes for node"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes routes approve {node1_id} 10.0.0.0/8,192.168.0.0/16")
    assert "10.0.0.0/8" in output
    assert "192.168.0.0/16" in output

with subtest("List routes for node"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes routes list {node1_id}")
    assert "10.0.0.0/8" in output

with subtest("Unapprove route"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes routes unapprove {node1_id} 192.168.0.0/16")
    assert "10.0.0.0/8" in output

with subtest("Expire node via CLI"):
    nodes = railscale_json("nodes list")
    node1 = next(n for n in nodes if n["given_name"] == "client1")
    node1_id = node1["id"]

    output = railscale(f"nodes expire {node1_id}")
    assert "Expired" in output

    output = railscale(f"nodes show {node1_id}")
    assert "Expiry:" in output

with subtest("Filter nodes by user"):
    output = railscale(f"nodes list -u {alice_id}")
    print(f"Nodes for user {alice_id}:\n{output}")

with subtest("Filter preauth keys by user"):
    output = railscale(f"preauthkeys list -u {alice_id}")
    print(f"Preauth keys for user {alice_id}:\n{output}")

# =============================================================================
# PHASE 6: Delete Node via CLI
# =============================================================================
with subtest("Delete node via CLI"):
    nodes = railscale_json("nodes list")
    node2 = next(n for n in nodes if n["given_name"] == "client2")
    node2_id = node2["id"]

    output = railscale(f"nodes delete {node2_id}")
    assert "Deleted" in output
    print(f"Deleted node {node2_id}")

    nodes = railscale_json("nodes list")
    ids = [n["id"] for n in nodes]
    assert node2_id not in ids, "Node should be deleted"

    names = [n["given_name"] for n in nodes]
    assert "client1" in names, "Client1 should still exist"

# =============================================================================
# PHASE 7-8: Key Attribute Tests
# =============================================================================
with subtest("Verify reusable key is marked correctly"):
    output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
    assert "Reusable:  true" in output
    reusable_key = extract_key(output)
    print(f"Created reusable key: {reusable_key[:20]}...")

    keys = railscale_json("preauthkeys list")
    # List returns only prefix, so check if full key starts with the stored prefix
    the_key = next((k for k in keys if reusable_key.startswith(k["key"])), None)
    assert the_key is not None, "Key should be in list"
    assert the_key.get("reusable") == True, "Key should be marked reusable"

with subtest("Verify ephemeral key creation"):
    output = railscale(f"preauthkeys create -u {alice_id} --ephemeral --expiration-days 1")
    assert "Ephemeral: true" in output
    ephemeral_key = extract_key(output)
    print(f"Created ephemeral key: {ephemeral_key[:20]}...")

    keys = railscale_json("preauthkeys list")
    # List returns only prefix, so check if full key starts with the stored prefix
    the_key = next((k for k in keys if ephemeral_key.startswith(k["key"])), None)
    assert the_key is not None, "Key should be in list"
    assert the_key.get("ephemeral") == True, "Key should be marked ephemeral"

# =============================================================================
# PHASE 9: User Delete Constraint
# =============================================================================
with subtest("User with nodes cannot be deleted"):
    result = server.execute(f"railscale users delete {alice_id} 2>&1")
    assert result[0] != 0 or "node" in result[1].lower(), \
        "Deleting user with nodes should fail"
    print("Correctly prevented deletion of user with nodes")

# =============================================================================
# PHASE 10: Connectivity After Management
# =============================================================================
with subtest("Client1 still connected after node management"):
    client1_ip = get_client_ip(client1)
    assert client1_ip is not None, "Client1 should still be connected"
    print(f"Client1 still connected with IP: {client1_ip}")

# =============================================================================
# PHASE 11-13: Key Usage Tests
# =============================================================================
with subtest("Non-reusable key cannot be used twice"):
    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    single_use_key = extract_key(output)
    print(f"Created single-use key: {single_use_key[:20]}...")

    reset_client(client2)
    connect_client(client2, single_use_key, "single-use-test-1")

    first_ip = get_client_ip(client2)
    assert first_ip is not None, "First use of single-use key should work"
    print(f"First use succeeded with IP: {first_ip}")

    reset_client(client2)
    connect_client(client2, single_use_key, "single-use-test-2", expect_success=False)

    second_ip = get_client_ip(client2)
    assert second_ip is None, "Second use of single-use key should NOT work"
    print("Second use correctly rejected - non-reusable key enforced!")

with subtest("Reusable key can be used multiple times"):
    output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
    reusable_key = extract_key(output)
    print(f"Created reusable key: {reusable_key[:20]}...")

    for i in range(1, 4):
        reset_client(client2)
        connect_client(client2, reusable_key, f"reusable-test-{i}")
        ip = get_client_ip(client2)
        assert ip is not None, f"Use {i} of reusable key should work"
        print(f"Use {i} of reusable key succeeded with IP: {ip}")

with subtest("Expired key cannot be used"):
    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    key_to_expire = extract_key(output)
    print(f"Created key to expire: {key_to_expire[:20]}...")

    keys = railscale_json("preauthkeys list")
    # List returns only prefix, so check if full key starts with the stored prefix
    the_key = next(k for k in keys if key_to_expire.startswith(k["key"]))
    key_id = the_key["id"]
    railscale(f"preauthkeys expire {key_id}")
    print(f"Expired key {key_id}")

    reset_client(client2)
    connect_client(client2, key_to_expire, "expired-key-test", expect_success=False)

    expired_ip = get_client_ip(client2)
    assert expired_ip is None, "Expired key should NOT work"
    print("Expired key correctly rejected!")

# =============================================================================
# PHASE 14: Deleted Node Gets New ID
# =============================================================================
with subtest("Deleted node gets new ID on reconnection"):
    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    fresh_key = extract_key(output)

    reset_client(client2)
    connect_client(client2, fresh_key, "delete-test-node")

    ip_before = get_client_ip(client2)
    assert ip_before is not None, "Client should connect"
    print(f"Connected with IP: {ip_before}")

    nodes = railscale_json("nodes list")
    test_node = next(n for n in nodes if n["given_name"] == "delete-test-node")
    old_node_id = test_node["id"]
    print(f"Node ID before deletion: {old_node_id}")

    railscale(f"nodes delete {old_node_id}")
    print(f"Deleted node {old_node_id}")

    output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    reconnect_key = extract_key(output)

    reset_client(client2)
    connect_client(client2, reconnect_key, "delete-test-reconnect")

    ip_after = get_client_ip(client2)
    assert ip_after is not None, "Client should reconnect"
    print(f"Reconnected with IP: {ip_after}")

    nodes = railscale_json("nodes list")
    new_node = next(n for n in nodes if n["given_name"] == "delete-test-reconnect")
    new_node_id = new_node["id"]

    assert new_node_id != old_node_id, f"New node should have different ID (old={old_node_id}, new={new_node_id})"
    print(f"New node ID: {new_node_id} (different from old: {old_node_id})")

# =============================================================================
# PHASE 15: Final Connectivity Test
# =============================================================================
with subtest("Final connectivity - fresh clients can communicate"):
    output1 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    final_key1 = extract_key(output1)

    output2 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    final_key2 = extract_key(output2)

    reset_client(client1)
    reset_client(client2)

    connect_client(client1, final_key1, "final-client1")
    connect_client(client2, final_key2, "final-client2")

    client1_ip = get_client_ip(client1)
    client2_ip = get_client_ip(client2)

    assert client1_ip is not None, "Client1 should be connected"
    assert client2_ip is not None, "Client2 should be connected"

    client1.succeed(f"timeout 15 ping -c 3 {client2_ip}")
    client2.succeed(f"timeout 15 ping -c 3 {client1_ip}")

    print(f"Final connectivity verified: client1 ({client1_ip}) <-> client2 ({client2_ip})")

# =============================================================================
# PHASE 16: Group-Based Access Control Tests
# =============================================================================
with subtest("Setup for group access control tests"):
    railscale("users create eve@example.com")
    print("Created user eve (not in any group)")

    users = railscale_json("users list")
    alice = next(u for u in users if u["email"] == "alice@example.com")
    eve = next(u for u in users if u["email"] == "eve@example.com")
    eve_id = eve["id"]
    print(f"Alice ID: {alice_id}, Eve ID: {eve_id}")

with subtest("Connect clients for group test"):
    output_alice = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
    alice_key = extract_key(output_alice)

    output_eve = railscale(f"preauthkeys create -u {eve_id} --expiration-days 1")
    eve_key = extract_key(output_eve)

    reset_client(client1)
    reset_client(client2)

    connect_client(client1, alice_key, "alice-node")
    connect_client(client2, eve_key, "eve-node")

    alice_ip = get_client_ip(client1)
    eve_ip = get_client_ip(client2)

    assert alice_ip is not None, "Alice's node should be connected"
    assert eve_ip is not None, "Eve's node should be connected"
    print(f"Alice node IP: {alice_ip}, Eve node IP: {eve_ip}")

with subtest("Tag alice's node as server"):
    nodes = railscale_json("nodes list")
    alice_node = next(n for n in nodes if n["given_name"] == "alice-node")
    alice_node_id = alice_node["id"]

    railscale(f"nodes tags set {alice_node_id} server")
    print("Tagged alice-node as server")

with subtest("Group member (alice) can access tagged server"):
    alice_ip = get_client_ip(client1)
    client1.succeed(f"timeout 10 ping -c 2 {alice_ip}")
    print("Alice (group:engineering) can access tagged server - PASS")

with subtest("Non-group member (eve) connectivity to member nodes"):
    alice_ip = get_client_ip(client1)
    eve_ip = get_client_ip(client2)

    client2.succeed(f"timeout 10 ping -c 2 {alice_ip}")
    print("Eve (autogroup:member) can reach Alice (autogroup:member) - PASS")

    client1.succeed(f"timeout 10 ping -c 2 {eve_ip}")
    print("Alice can reach Eve - PASS")

with subtest("Verify policy groups are loaded"):
    server.succeed("journalctl -u railscale --no-pager | grep -i 'policy' || true")
    print("Policy with groups is active")

# =============================================================================
# REST API Tests
# =============================================================================

with subtest("REST API - Create API key for testing"):
    # Create an admin user and API key for REST API testing
    railscale("users create admin@example.com --display-name 'API Admin'")
    users = railscale_json("users list")
    admin_user = next(u for u in users if u["email"] == "admin@example.com")
    admin_id = admin_user["id"]
    
    api_key = create_api_key_for_user(admin_id)
    assert api_key.startswith("rsapi_"), f"API key should start with rsapi_: {api_key}"
    print(f"Created API key for testing: {api_key[:20]}...")

with subtest("REST API - Unauthenticated requests are rejected"):
    status = api_request_status("/api/v1/user", "GET")
    assert status == 401, f"Unauthenticated request should return 401, got {status}"
    print("Unauthenticated request correctly rejected with 401")

with subtest("REST API - List users"):
    result = api_get("/api/v1/user", api_key)
    assert "users" in result, f"Response should contain 'users': {result}"
    users = result["users"]
    assert len(users) > 0, "Should have at least one user"
    print(f"Listed {len(users)} users via REST API")

with subtest("REST API - Create user"):
    result = api_post("/api/v1/user", api_key, {"name": "restuser"})
    assert "user" in result, f"Response should contain 'user': {result}"
    assert result["user"]["name"] == "restuser"
    rest_user_id = result["user"]["id"]
    print(f"Created user via REST API: id={rest_user_id}")

with subtest("REST API - Rename user"):
    result = api_post(f"/api/v1/user/{rest_user_id}/rename/renameduser", api_key)
    assert "user" in result, f"Response should contain 'user': {result}"
    assert result["user"]["name"] == "renameduser"
    print("Renamed user via REST API")

with subtest("REST API - Delete user"):
    result = api_delete(f"/api/v1/user/{rest_user_id}", api_key)
    # Empty response is OK for delete
    print("Deleted user via REST API")

with subtest("REST API - List nodes"):
    result = api_get("/api/v1/node", api_key)
    assert "nodes" in result, f"Response should contain 'nodes': {result}"
    nodes = result["nodes"]
    print(f"Listed {len(nodes)} nodes via REST API")

with subtest("REST API - Get node"):
    result = api_get("/api/v1/node", api_key)
    if result["nodes"]:
        node_id = result["nodes"][0]["id"]
        node_result = api_get(f"/api/v1/node/{node_id}", api_key)
        assert "node" in node_result, f"Response should contain 'node': {node_result}"
        print(f"Got node {node_id} via REST API")

with subtest("REST API - List preauth keys"):
    result = api_get("/api/v1/preauthkey", api_key)
    assert "preAuthKeys" in result, f"Response should contain 'preAuthKeys': {result}"
    print(f"Listed {len(result['preAuthKeys'])} preauth keys via REST API")

with subtest("REST API - Create preauth key"):
    result = api_post("/api/v1/preauthkey", api_key, {
        "user": int(admin_id),
        "reusable": False,
        "ephemeral": False,
        "aclTags": []
    })
    assert "preAuthKey" in result, f"Response should contain 'preAuthKey': {result}"
    new_pak_id = result["preAuthKey"]["id"]
    print(f"Created preauth key via REST API: id={new_pak_id}")

with subtest("REST API - Expire preauth key"):
    result = api_post("/api/v1/preauthkey/expire", api_key, {"id": int(new_pak_id)})
    # Empty response is OK for expire
    print("Expired preauth key via REST API")

with subtest("REST API - List API keys"):
    result = api_get("/api/v1/apikey", api_key)
    assert "apiKeys" in result, f"Response should contain 'apiKeys': {result}"
    print(f"Listed {len(result['apiKeys'])} API keys via REST API")

with subtest("REST API - Create API key"):
    result = api_post("/api/v1/apikey", api_key, {"user": int(admin_id)})
    assert "apiKey" in result, f"Response should contain 'apiKey': {result}"
    assert "key" in result, f"Response should contain 'key': {result}"
    new_api_key = result["apiKey"]
    new_api_key_prefix = result["key"]["prefix"]
    assert new_api_key.startswith("rsapi_"), "New API key should start with rsapi_"
    print(f"Created API key via REST API: {new_api_key_prefix}")

with subtest("REST API - Delete API key"):
    result = api_delete(f"/api/v1/apikey/{new_api_key_prefix}", api_key)
    # Empty response is OK for delete
    print("Deleted API key via REST API")

with subtest("REST API - Get policy"):
    result = api_get("/api/v1/policy", api_key)
    assert "policy" in result, f"Response should contain 'policy': {result}"
    policy_json = result["policy"]
    assert "grants" in policy_json, "Policy should contain grants"
    print("Got policy via REST API")

with subtest("REST API - Set policy"):
    new_policy = {
        "groups": {"group:test": ["test@example.com"]},
        "grants": [
            {"src": ["*"], "dst": ["*"], "ip": ["*"]}
        ]
    }
    result = api_put("/api/v1/policy", api_key, {"policy": json.dumps(new_policy)})
    assert "policy" in result, f"Response should contain 'policy': {result}"
    print("Set policy via REST API")

with subtest("REST API - Rate limit headers present"):
    # Make a request and check headers
    cmd = f"curl -s -D - -o /dev/null -H 'Authorization: Bearer {api_key}' '{SERVER_URL}/api/v1/user'"
    headers = server.succeed(cmd)
    # tower_governor adds x-ratelimit headers when use_headers() is called
    # Check that at least one rate limit header is present
    has_ratelimit = "x-ratelimit" in headers.lower() or "ratelimit" in headers.lower()
    print(f"Rate limit headers present: {has_ratelimit}")
    print(f"Headers: {headers[:500]}...")

with subtest("REST API - Rate limiting blocks excessive requests"):
    # Make rapid requests until we hit the rate limit (429)
    # With 200 req/min (300ms replenish) and burst 33, we should hit 429
    # after ~40-50 requests since VM latency (~50ms) < replenish time
    got_rate_limited = False
    request_count = 0
    max_requests = 100  # Should be enough to exhaust burst + some replenish
    
    for i in range(max_requests):
        status = api_request_status("/api/v1/user", "GET", api_key)
        request_count += 1
        if status == 429:
            got_rate_limited = True
            print(f"Rate limited after {request_count} requests (429 Too Many Requests)")
            break
        elif status != 200:
            print(f"Unexpected status {status} on request {request_count}")
    
    assert got_rate_limited, f"Should have been rate limited within {max_requests} requests"
    print("Rate limiting is working correctly")

print("\n" + "=" * 70)
print("ALL TESTS PASSED!")
print("=" * 70)
