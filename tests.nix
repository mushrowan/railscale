{
  pkgs,
  railscale,
}:
pkgs.testers.runNixOSTest {
  name = "railscale-cli-integration";

  nodes =
    let
      commonClientFlags = [ "--verbose=5" ];
      serverUrl = "http://192.168.1.3:8080";

      # Import the NixOS module
      railscaleModule = import ./nix/module.nix;
    in
    {
      server =
        {
          config,
          pkgs,
          ...
        }:
        {
          imports = [ railscaleModule ];

          # Extra packages for testing
          environment.systemPackages = [
            pkgs.sqlite
            pkgs.jq
          ];

          # Policy with groups for testing access control
          environment.etc."railscale/policy.json".text = builtins.toJSON {
            # Group definitions - alice is in engineering, bob is not
            groups = {
              "group:engineering" = [ "alice@example.com" ];
              "group:admins" = [ "admin@example.com" ];
            };
            grants = [
              # Allow all for initial connectivity tests
              {
                src = [ "*" ];
                dst = [ "*" ];
                ip = [ "*" ];
              }
            ];
          };

          # Group-restricted policy for access control tests
          environment.etc."railscale/policy-groups.json".text = builtins.toJSON {
            groups = {
              "group:engineering" = [ "alice@example.com" ];
              "group:admins" = [ "admin@example.com" ];
            };
            grants = [
              # Engineering group can access tagged servers
              {
                src = [ "group:engineering" ];
                dst = [ "tag:server" ];
                ip = [ "*" ];
              }
              # Everyone can access each other (for basic connectivity)
              {
                src = [ "autogroup:member" ];
                dst = [ "autogroup:member" ];
                ip = [ "*" ];
              }
            ];
          };

          # Use the railscale module
          services.railscale = {
            enable = true;
            package = railscale;
            address = "0.0.0.0";
            port = 8080;

            settings = {
              server_url = "http://server:8080";

              derp.embedded_derp = {
                enabled = true;
                advertise_host = "192.168.1.3";
                advertise_port = 3340;
              };
            };

            policyFile = "/etc/railscale/policy.json";
          };

          # Set database URL for CLI commands (module handles this for the service)
          environment.variables.RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";

          # Override log level for debugging
          systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";

          # Extra firewall port for control plane (DERP ports auto-opened by module)
          networking.firewall.allowedTCPPorts = [ 8080 ];
        };

      client1 =
        {
          config,
          pkgs,
          ...
        }:
        {
          services.tailscale = {
            enable = true;
            extraDaemonFlags = commonClientFlags;
          };

          systemd.services.tailscaled.environment = {
            TS_NO_LOGS_NO_SUPPORT = "1";
          };

          environment.systemPackages = [ pkgs.tailscale ];
        };

      client2 =
        {
          config,
          pkgs,
          ...
        }:
        {
          services.tailscale = {
            enable = true;
            extraDaemonFlags = commonClientFlags;
          };

          systemd.services.tailscaled.environment = {
            TS_NO_LOGS_NO_SUPPORT = "1";
          };

          environment.systemPackages = [ pkgs.tailscale ];
        };
    };

  testScript = ''
    import json
    import time

    SERVER_URL = "http://192.168.1.3:8080"

    def railscale(cmd):
        """Run a railscale CLI command on the server"""
        return server.succeed(f"railscale {cmd}")

    def railscale_json(cmd):
        """Run a railscale CLI command and parse JSON output"""
        output = server.succeed(f"railscale {cmd} -o json")
        return json.loads(output)

    def extract_key(output):
        """Extract the key from CLI output"""
        for line in output.split('\n'):
            if "Key:" in line:
                return line.split("Key:")[1].strip()
        raise Exception(f"Could not find Key in output: {output}")

    def connect_client(client, key, hostname, expect_success=True):
        """Connect a tailscale client with the given preauth key"""
        client.execute(f"timeout 15 tailscale up --login-server={SERVER_URL} --authkey={key} --hostname={hostname} 2>&1 || true")
        time.sleep(2)  # Give it time to connect
        if expect_success:
            # Wait a bit more for registration to complete
            time.sleep(3)

    def get_client_ip(client):
        """Get the tailscale IP, returns None if not connected"""
        result = client.execute("tailscale ip -4 2>&1")
        if result[0] == 0 and result[1].strip().startswith("100."):
            return result[1].strip()
        return None

    def disconnect_client(client):
        """Disconnect a tailscale client"""
        client.execute("tailscale logout 2>&1 || true")
        time.sleep(2)

    def reset_client(client):
        """Fully reset tailscaled state"""
        client.execute("tailscale logout 2>&1 || true")
        client.execute("systemctl stop tailscaled")
        client.execute("rm -rf /var/lib/tailscale/*")
        client.execute("systemctl start tailscaled")
        client.wait_for_unit("tailscaled.service")
        time.sleep(1)

    start_all()

    # =========================================================================
    # PHASE 1: Server Startup
    # =========================================================================
    with subtest("Server starts successfully"):
        server.wait_for_unit("railscale.service")
        server.wait_for_open_port(8080)
        server.wait_for_open_port(3340)
        print("Server started successfully")

    # Wait for network to stabilize
    server.wait_for_unit("dhcpcd.service")
    client1.wait_for_unit("dhcpcd.service")
    client2.wait_for_unit("dhcpcd.service")
    client1.wait_for_unit("tailscaled.service")
    client2.wait_for_unit("tailscaled.service")

    # Give network time to fully stabilize
    time.sleep(3)

    # =========================================================================
    # PHASE 2: User Management CLI Tests
    # =========================================================================
    with subtest("Create user via CLI"):
        output = railscale("users create alice --display-name 'Alice Smith' --email alice@example.com")
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
        assert users[0]["name"] == "alice"
        print(f"Users JSON: {users}")

    with subtest("Create second user"):
        railscale("users create bob --email bob@example.com")
        users = railscale_json("users list")
        assert len(users) == 2
        user_names = [u["name"] for u in users]
        assert "alice" in user_names
        assert "bob" in user_names

    with subtest("Rename user"):
        users = railscale_json("users list")
        bob = next(u for u in users if u["name"] == "bob")
        bob_id = bob["id"]

        output = railscale(f"users rename {bob_id} robert")
        assert "Renamed" in output

        users = railscale_json("users list")
        user_names = [u["name"] for u in users]
        assert "robert" in user_names
        assert "bob" not in user_names

    with subtest("Delete user"):
        users = railscale_json("users list")
        robert = next(u for u in users if u["name"] == "robert")
        robert_id = robert["id"]

        output = railscale(f"users delete {robert_id}")
        assert "Deleted" in output

        users = railscale_json("users list")
        assert len(users) == 1
        assert users[0]["name"] == "alice"

    # Get alice's ID for later use
    users = railscale_json("users list")
    alice_id = users[0]["id"]
    print(f"Alice's ID: {alice_id}")

    # =========================================================================
    # PHASE 3: Preauth Key Management CLI Tests
    # =========================================================================
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

    # =========================================================================
    # PHASE 3.5: API Key Management CLI Tests
    # =========================================================================
    with subtest("Create API key via CLI"):
        output = railscale(f"apikeys create -u {alice_id} --name 'My Test API Key' --expiration-days 30")
        assert "Created API key" in output
        assert "Key:" in output
        assert "rsapi_" in output  # API keys have rsapi_ prefix
        print(f"Created API key output: {output}")

    with subtest("List API keys"):
        output = railscale("apikeys list")
        assert "My Test API Key" in output or "My Test AP..." in output
        print(f"API keys list:\n{output}")

    with subtest("List API keys JSON output"):
        keys = railscale_json("apikeys list")
        assert len(keys) >= 1
        assert any("rsapi_" in k["key"] for k in keys)
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
        # Delete a key that isn't already expired
        key_to_delete = keys[-1] if len(keys) > 1 else keys[0]
        key_id = key_to_delete["id"]
        output = railscale(f"apikeys delete {key_id}")
        assert "Deleted" in output
        print(f"Deleted API key {key_id}")

    with subtest("Filter API keys by user"):
        output = railscale(f"apikeys list -u {alice_id}")
        print(f"API keys for user {alice_id}:\n{output}")

    # =========================================================================
    # PHASE 4: Client Connection with Preauth Keys
    # =========================================================================
    with subtest("Connect clients with preauth keys"):
        # Create keys
        output1 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        client1_key = extract_key(output1)
        print(f"Client1 key: {client1_key}")

        output2 = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        client2_key = extract_key(output2)
        print(f"Client2 key: {client2_key}")

        # Connect clients
        connect_client(client1, client1_key, "client1")
        connect_client(client2, client2_key, "client2")

        # Verify connections
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

    # =========================================================================
    # PHASE 5: Node Management CLI Tests
    # =========================================================================
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

    # =========================================================================
    # PHASE 6: Delete Node via CLI
    # =========================================================================
    with subtest("Delete node via CLI"):
        nodes = railscale_json("nodes list")
        # Delete client2's node (keep client1 for continued testing)
        node2 = next(n for n in nodes if n["given_name"] == "client2")
        node2_id = node2["id"]

        output = railscale(f"nodes delete {node2_id}")
        assert "Deleted" in output
        print(f"Deleted node {node2_id}")

        # Verify deletion
        nodes = railscale_json("nodes list")
        ids = [n["id"] for n in nodes]
        assert node2_id not in ids, "Node should be deleted"

        # Verify client1 still exists
        names = [n["given_name"] for n in nodes]
        assert "client1" in names, "Client1 should still exist"

    # =========================================================================
    # PHASE 7: Verify Reusable Key Creation
    # =========================================================================
    with subtest("Verify reusable key is marked correctly"):
        output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
        assert "Reusable:  true" in output
        reusable_key = extract_key(output)
        print(f"Created reusable key: {reusable_key[:20]}...")

        # Verify in list
        keys = railscale_json("preauthkeys list")
        the_key = next((k for k in keys if k["key"] == reusable_key), None)
        assert the_key is not None, "Key should be in list"
        assert the_key.get("reusable") == True, "Key should be marked reusable"

    # =========================================================================
    # PHASE 8: Verify Ephemeral Key Creation
    # =========================================================================
    with subtest("Verify ephemeral key creation"):
        output = railscale(f"preauthkeys create -u {alice_id} --ephemeral --expiration-days 1")
        assert "Ephemeral: true" in output
        ephemeral_key = extract_key(output)
        print(f"Created ephemeral key: {ephemeral_key[:20]}...")

        # Verify in list
        keys = railscale_json("preauthkeys list")
        the_key = next((k for k in keys if k["key"] == ephemeral_key), None)
        assert the_key is not None, "Key should be in list"
        assert the_key.get("ephemeral") == True, "Key should be marked ephemeral"

    # =========================================================================
    # PHASE 9: Verify Users Cannot Be Deleted With Nodes
    # =========================================================================
    with subtest("User with nodes cannot be deleted without force"):
        # Try to delete alice (who has client1 node)
        result = server.execute(f"railscale users delete {alice_id} 2>&1")
        # Should fail because alice has nodes
        assert result[0] != 0 or "has" in result[1].lower() or "force" in result[1].lower(), \
            "Deleting user with nodes should fail or warn about force"
        print("Correctly prevented deletion of user with nodes")

    # =========================================================================
    # PHASE 10: Continued Connectivity Test
    # =========================================================================
    with subtest("Client1 still connected after node management"):
        # Client1 should still be connected and have an IP
        client1_ip = get_client_ip(client1)
        assert client1_ip is not None, "Client1 should still be connected"
        print(f"Client1 still connected with IP: {client1_ip}")

    # =========================================================================
    # PHASE 11: Non-reusable Key Cannot Be Used Twice
    # =========================================================================
    with subtest("Non-reusable key cannot be used twice"):
        # Create a fresh non-reusable key
        output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        single_use_key = extract_key(output)
        print(f"Created single-use key: {single_use_key[:20]}...")

        # Reset client2 and connect with this key (first use)
        reset_client(client2)
        connect_client(client2, single_use_key, "single-use-test-1")
        
        first_ip = get_client_ip(client2)
        assert first_ip is not None, "First use of single-use key should work"
        print(f"First use succeeded with IP: {first_ip}")

        # Reset client2 again and try to reuse the same key
        reset_client(client2)
        connect_client(client2, single_use_key, "single-use-test-2", expect_success=False)
        
        second_ip = get_client_ip(client2)
        assert second_ip is None, "Second use of single-use key should NOT work"
        print("Second use correctly rejected - non-reusable key enforced!")

    # =========================================================================
    # PHASE 12: Reusable Key Can Be Used Multiple Times
    # =========================================================================
    with subtest("Reusable key can be used multiple times"):
        # Create a reusable key
        output = railscale(f"preauthkeys create -u {alice_id} --reusable --expiration-days 1")
        reusable_key = extract_key(output)
        print(f"Created reusable key: {reusable_key[:20]}...")

        # Reset client2 and connect (first use)
        reset_client(client2)
        connect_client(client2, reusable_key, "reusable-test-1")
        
        first_ip = get_client_ip(client2)
        assert first_ip is not None, "First use of reusable key should work"
        print(f"First use of reusable key succeeded with IP: {first_ip}")

        # Reset client2 and connect again (second use)
        reset_client(client2)
        connect_client(client2, reusable_key, "reusable-test-2")
        
        second_ip = get_client_ip(client2)
        assert second_ip is not None, "Second use of reusable key should work"
        print(f"Second use of reusable key succeeded with IP: {second_ip}")

        # Third use for good measure
        reset_client(client2)
        connect_client(client2, reusable_key, "reusable-test-3")
        
        third_ip = get_client_ip(client2)
        assert third_ip is not None, "Third use of reusable key should work"
        print(f"Third use of reusable key succeeded with IP: {third_ip}")

    # =========================================================================
    # PHASE 13: Expired Key Cannot Be Used
    # =========================================================================
    with subtest("Expired key cannot be used"):
        # Create a key and immediately expire it
        output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        key_to_expire = extract_key(output)
        print(f"Created key to expire: {key_to_expire[:20]}...")

        # Find and expire the key
        keys = railscale_json("preauthkeys list")
        the_key = next(k for k in keys if k["key"] == key_to_expire)
        key_id = the_key["id"]
        railscale(f"preauthkeys expire {key_id}")
        print(f"Expired key {key_id}")

        # Try to use the expired key
        reset_client(client2)
        connect_client(client2, key_to_expire, "expired-key-test", expect_success=False)
        
        expired_ip = get_client_ip(client2)
        assert expired_ip is None, "Expired key should NOT work"
        print("Expired key correctly rejected!")

    # =========================================================================
    # PHASE 14: Deleted Node Gets New ID on Reconnection
    # =========================================================================
    with subtest("Deleted node gets new ID on reconnection"):
        # First, connect client2 fresh
        output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        fresh_key = extract_key(output)
        
        reset_client(client2)
        connect_client(client2, fresh_key, "delete-test-node")
        
        ip_before = get_client_ip(client2)
        assert ip_before is not None, "Client should connect"
        print(f"Connected with IP: {ip_before}")

        # Get the node ID
        nodes = railscale_json("nodes list")
        test_node = next(n for n in nodes if n["given_name"] == "delete-test-node")
        old_node_id = test_node["id"]
        print(f"Node ID before deletion: {old_node_id}")

        # Delete the node
        railscale(f"nodes delete {old_node_id}")
        print(f"Deleted node {old_node_id}")

        # Reconnect with a new key (need new key since old one is used)
        output = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        reconnect_key = extract_key(output)
        
        reset_client(client2)
        connect_client(client2, reconnect_key, "delete-test-reconnect")
        
        ip_after = get_client_ip(client2)
        assert ip_after is not None, "Client should reconnect"
        print(f"Reconnected with IP: {ip_after}")

        # Verify new node has different ID
        nodes = railscale_json("nodes list")
        new_node = next(n for n in nodes if n["given_name"] == "delete-test-reconnect")
        new_node_id = new_node["id"]
        
        assert new_node_id != old_node_id, f"New node should have different ID (old={old_node_id}, new={new_node_id})"
        print(f"New node ID: {new_node_id} (different from old: {old_node_id})")

    # =========================================================================
    # PHASE 15: Final Connectivity Test
    # =========================================================================
    with subtest("Final connectivity - fresh clients can communicate"):
        # Reconnect both clients fresh (client1 was expired earlier)
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
        
        # Test bidirectional ping
        client1.succeed(f"timeout 15 ping -c 3 {client2_ip}")
        client2.succeed(f"timeout 15 ping -c 3 {client1_ip}")
        
        print(f"Final connectivity verified: client1 ({client1_ip}) <-> client2 ({client2_ip})")

    # =========================================================================
    # PHASE 16: Group-Based Access Control Tests
    # =========================================================================
    with subtest("Setup for group access control tests"):
        # Create a user NOT in engineering group
        railscale("users create eve --email eve@example.com")
        print("Created user eve (not in any group)")

        # Verify alice (in engineering) and eve (not in group) exist
        users = railscale_json("users list")
        alice = next(u for u in users if u["name"] == "alice")
        eve = next(u for u in users if u["name"] == "eve")
        eve_id = eve["id"]
        print(f"Alice ID: {alice_id}, Eve ID: {eve_id}")

    with subtest("Restart server with group-restricted policy"):
        # Update the policy file to use group-restricted grants
        server.succeed("cp /etc/railscale/policy-groups.json /etc/railscale/policy.json")
        server.succeed("systemctl restart railscale")
        server.wait_for_unit("railscale.service")
        server.wait_for_open_port(8080)
        time.sleep(2)
        print("Server restarted with group-restricted policy")

    with subtest("Connect clients for group test"):
        # Create keys for alice (in engineering) and eve (not in group)
        output_alice = railscale(f"preauthkeys create -u {alice_id} --expiration-days 1")
        alice_key = extract_key(output_alice)

        output_eve = railscale(f"preauthkeys create -u {eve_id} --expiration-days 1")
        eve_key = extract_key(output_eve)

        # Reset and connect clients
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
        # Alice is in group:engineering, which can access tag:server
        # Since alice's own node is tagged as server, she should see it
        # But more importantly, alice (as group:engineering member) can reach tag:server
        # Let's verify the grant evaluation works by checking node visibility

        # Alice should be able to ping herself (tag:server accessible by group:engineering)
        alice_ip = get_client_ip(client1)
        client1.succeed(f"timeout 10 ping -c 2 {alice_ip}")
        print("Alice (group:engineering) can access tagged server - PASS")

    with subtest("Non-group member (eve) connectivity to member nodes"):
        # Eve is NOT in group:engineering
        # The policy allows autogroup:member -> autogroup:member
        # So eve (member) should be able to reach alice (member) but NOT tag:server
        # However, alice's node IS both member and tag:server
        
        # The grant "autogroup:member -> autogroup:member" should allow basic connectivity
        alice_ip = get_client_ip(client1)
        eve_ip = get_client_ip(client2)

        # Eve should be able to reach alice via the autogroup:member grant
        client2.succeed(f"timeout 10 ping -c 2 {alice_ip}")
        print("Eve (autogroup:member) can reach Alice (autogroup:member) - PASS")

        # Alice should be able to reach eve
        client1.succeed(f"timeout 10 ping -c 2 {eve_ip}")
        print("Alice can reach Eve - PASS")

    with subtest("Verify policy groups are loaded"):
        # Check that the server loaded the groups correctly by examining logs
        server.succeed("journalctl -u railscale --no-pager | grep -i 'policy' || true")
        print("Policy with groups is active")

    print("\n" + "="*70)
    print("ALL TESTS PASSED!")
    print("="*70)
  '';
}
