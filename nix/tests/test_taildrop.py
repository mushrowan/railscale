# Taildrop (file sharing) tests
# ruff: noqa: F821, F811
# pyright: reportUndefinedVariable=false, reportUnboundVariable=false

# Requires: alice_id from test_users.py
# time module is imported in helpers.py

# =============================================================================
# PHASE: Taildrop Setup - Reconnect Clients
# =============================================================================

with subtest("Taildrop: setup clients"):
    # test_nodes.py may have deleted/expired nodes, so reconnect fresh
    reset_client(client1)
    reset_client(client2)
    
    key1 = create_preauth_key(alice_id, expiration_days=1)
    key2 = create_preauth_key(alice_id, expiration_days=1)
    
    connect_client(client1, key1, "client1")
    connect_client(client2, key2, "client2")
    
    # verify both clients are connected
    client1_ip = get_client_ip(client1)
    client2_ip = get_client_ip(client2)
    assert client1_ip is not None, "client1 should have IP"
    assert client2_ip is not None, "client2 should have IP"
    print(f"Taildrop test clients connected: {client1_ip}, {client2_ip}")

# =============================================================================
# PHASE: Taildrop File Transfer Tests (Same User)
# =============================================================================

with subtest("Taildrop: verify peers can communicate"):
    # first ensure peers can ping each other (needed for taildrop)
    client2_ip = get_client_ip(client2)
    client1_ip = get_client_ip(client1)
    
    # wait for DERP connection to establish
    time.sleep(5)
    
    # try pinging via tailscale
    ping_result = client1.execute(f"tailscale ping --c 3 {client2_ip} 2>&1")
    print(f"tailscale ping result: {ping_result}")
    
    # check tailscale status
    status1 = client1.execute("tailscale status 2>&1")
    print(f"client1 status after ping:\n{status1[1]}")

with subtest("Taildrop: check self node capabilities"):
    # debug: check if the client sees file sharing capability on self node
    # use tailscale status --json to see what the client knows
    status_json = client1.execute("tailscale status --json 2>&1")
    print(f"client1 status json (first 2000 chars): {status_json[1][:2000]}")
    
    # also check debug prefs
    debug_prefs = client1.execute("tailscale debug prefs 2>&1")
    print(f"client1 debug prefs: {debug_prefs[1][:1000]}")

with subtest("Taildrop: check file targets are visible"):
    # both clients should see each other as file targets (same user)
    result1 = client1.execute("tailscale file cp --targets 2>&1")
    result2 = client2.execute("tailscale file cp --targets 2>&1")
    
    print(f"client1 file targets: {result1}")
    print(f"client2 file targets: {result2}")
    
    # at minimum, the command should succeed
    assert result1[0] == 0, f"client1 file targets failed: {result1[1]}"
    assert result2[0] == 0, f"client2 file targets failed: {result2[1]}"
    
    # each client should see the other as a target
    assert "client2" in result1[1], f"client1 should see client2 as target: {result1[1]}"
    assert "client1" in result2[1], f"client2 should see client1 as target: {result2[1]}"
    print("Both clients can see each other as file targets")

with subtest("Taildrop: send file from client1 to client2"):
    # create a test file on client1
    test_content = "hello from taildrop test!"
    client1.succeed(f"echo '{test_content}' > /tmp/taildrop-test.txt")
    
    # send file to client2
    client1.succeed("tailscale file cp /tmp/taildrop-test.txt client2: 2>&1")
    print("File sent from client1 to client2")

with subtest("Taildrop: receive file on client2"):
    # wait a moment for file to arrive
    time.sleep(2)
    
    # get files into /tmp/received
    client2.succeed("mkdir -p /tmp/received")
    client2.succeed("tailscale file get /tmp/received/ 2>&1")
    
    # verify file content
    received = client2.succeed("cat /tmp/received/taildrop-test.txt").strip()
    expected = "hello from taildrop test!"
    assert received == expected, f"File content mismatch: got '{received}', expected '{expected}'"
    print(f"File received successfully with correct content: {received}")

with subtest("Taildrop: bidirectional transfer"):
    # send file back from client2 to client1
    client2.succeed("echo 'reply from client2' > /tmp/reply.txt")
    client2.succeed("tailscale file cp /tmp/reply.txt client1: 2>&1")
    
    time.sleep(2)
    
    # receive on client1
    client1.succeed("mkdir -p /tmp/received")
    client1.succeed("tailscale file get /tmp/received/ 2>&1")
    
    received = client1.succeed("cat /tmp/received/reply.txt").strip()
    assert received == "reply from client2", f"Reply content mismatch: {received}"
    print("Bidirectional file transfer works!")

# =============================================================================
# PHASE: Taildrop Cross-User Blocking
# =============================================================================

with subtest("Taildrop: cross-user file sharing is blocked"):
    # create a second user (bob)
    bob_id = create_user_and_get_id("bob@example.com", "Bob")
    print(f"Created bob with id: {bob_id}")
    
    # disconnect client2 and reconnect as bob
    reset_client(client2)
    bob_key = create_preauth_key(bob_id, expiration_days=1)
    connect_client(client2, bob_key, "client2-bob")
    
    # wait for reconnection
    time.sleep(3)
    
    # verify client2 is now bob's device
    client2_ip = get_client_ip(client2)
    assert client2_ip is not None, "client2 should have IP after reconnecting as bob"
    print(f"client2 reconnected as bob with IP: {client2_ip}")
    
    # client1 (alice) should NOT see client2 (bob) as a file target
    targets_result = client1.execute("tailscale file cp --targets 2>&1")
    # bob's device should not appear as a target for alice
    assert "client2-bob" not in targets_result[1], \
        f"alice should NOT see bob's device as file target: {targets_result[1]}"
    print("Cross-user file sharing correctly blocked - bob's device not visible to alice")
    
    # try sending a file anyway (should fail)
    client1.succeed("echo 'secret' > /tmp/secret.txt")
    send_result = client1.execute(f"tailscale file cp /tmp/secret.txt {client2_ip}: 2>&1")
    # the send should fail or the file should not be receivable
    if send_result[0] == 0:
        # if send "succeeded", verify file is not actually received
        time.sleep(2)
        client2.succeed("mkdir -p /tmp/bob-received")
        get_result = client2.execute("tailscale file get /tmp/bob-received/ 2>&1")
        # either get fails or no files received
        files = client2.execute("ls /tmp/bob-received/ 2>&1")
        assert "secret.txt" not in files[1], \
            f"bob should NOT receive alice's file: {files[1]}"
    print("Cross-user file transfer correctly blocked!")
    
    # reconnect client2 as alice for remaining tests
    reset_client(client2)
    alice_key = create_preauth_key(alice_id, expiration_days=1)
    connect_client(client2, alice_key, "client2")
    time.sleep(2)
    print("client2 reconnected as alice for remaining tests")
