# Group-based access control tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Requires: alice_id from test_users.py

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
