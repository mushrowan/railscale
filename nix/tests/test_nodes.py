# Node management and connectivity tests
# ruff: noqa: F821
# pyright: reportUndefinedVariable=false

# Requires: alice_id from test_users.py

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
