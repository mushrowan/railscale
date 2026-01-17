{
  pkgs,
  railscale,
}:
pkgs.testers.runNixOSTest {
  name = "railscale-cli-integration";

  nodes =
    let
      commonClientFlags = [ "--verbose=5" ];
      dbUrl = "sqlite:///var/lib/railscale/db.sqlite";
      serverUrl = "http://192.168.1.3:8080";
    in
    {
      server =
        {
          config,
          pkgs,
          ...
        }:
        {
          environment.systemPackages = [
            railscale
            pkgs.sqlite
            pkgs.jq
          ];

          # Allow-all policy for testing
          environment.etc."railscale/policy.json".text = builtins.toJSON {
            grants = [
              {
                src = [ "*" ];
                dst = [ "*" ];
                ip = [ "*" ];
              }
            ];
          };

          # Set database URL for CLI commands
          environment.variables.RAILSCALE_DATABASE_URL = dbUrl;

          systemd.services.railscale = {
            description = "Railscale Control Server";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ];

            environment = {
              RAILSCALE_DATABASE_URL = dbUrl;
              RAILSCALE_LISTEN_ADDR = "0.0.0.0:8080";
              RAILSCALE_SERVER_URL = "http://server:8080";
              RAILSCALE_POLICY_FILE = "/etc/railscale/policy.json";
              RAILSCALE_LOG_LEVEL = "debug";
              RAILSCALE_DERP_EMBEDDED_ENABLED = "true";
              RAILSCALE_DERP_ADVERTISE_HOST = "192.168.1.3";
              RAILSCALE_DERP_ADVERTISE_PORT = "3340";
            };

            serviceConfig = {
              ExecStart = "${pkgs.lib.getExe railscale} serve";
              StateDirectory = "railscale";
              Restart = "on-failure";
            };
          };

          networking.firewall.allowedTCPPorts = [
            8080
            3340
          ];
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

    print("\n" + "="*70)
    print("ALL CLI INTEGRATION TESTS PASSED!")
    print("="*70)
  '';
}
