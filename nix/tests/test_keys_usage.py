# Key attribute and usage tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Requires: alice_id from test_users.py

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
    exit_code, output = server.execute(f"railscale users delete {alice_id} 2>&1")
    assert exit_code != 0 or "node" in output.lower(), \
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
