{
  pkgs,
  railscale,
}:
pkgs.testers.runNixOSTest {
  name = "railscale-tailscale-integration";

  nodes = let commonClientFlags = ["--verbose=3"]; in {
    server = {
      config,
      pkgs,
      ...
    }: {
      environment.systemPackages = [railscale pkgs.sqlite];

      # Allow-all policy for testing
      environment.etc."railscale/policy.json".text = builtins.toJSON {
        grants = [
          {
            src = ["*"];
            dst = ["*"];
            ip = ["*"];
          }
        ];
      };

      systemd.services.railscale = {
        description = "Railscale Control Server";
        wantedBy = ["multi-user.target"];
        after = ["network.target"];

        environment = {
          RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";
          RAILSCALE_LISTEN_ADDR = "0.0.0.0:8080";
          RAILSCALE_SERVER_URL = "http://server:8080";
          RAILSCALE_POLICY_FILE = "/etc/railscale/policy.json";
          RAILSCALE_LOG_LEVEL = "trace";
        };

        serviceConfig = {
          ExecStart = "${pkgs.lib.getExe railscale}";
          StateDirectory = "railscale";
          Restart = "on-failure";
        };
      };

      networking.firewall.allowedTCPPorts = [8080];
    };

    client1 = {
      config,
      pkgs,
      ...
    }: {
      services.tailscale = {
        enable = true;
        extraDaemonFlags = commonClientFlags;
      };

      environment.systemPackages = [pkgs.tailscale];
    };

    client2 = {
      config,
      pkgs,
      ...
    }: {
      services.tailscale = {
        enable = true;
        extraDaemonFlags = commonClientFlags;
      };

      environment.systemPackages = [pkgs.tailscale];
    };
  };

  testScript = ''
    start_all()

    # Wait for railscale server to start
    server.wait_for_unit("railscale.service")
    server.wait_for_open_port(8080)

    # Create a user and two preauth keys
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO users (id, name, created_at, updated_at) VALUES (1, 'testuser', datetime('now'), datetime('now'));\"")
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO preauth_keys (id, key, user_id, reusable, ephemeral, used, created_at, expiration) VALUES (1, 'preauth-key-client1', 1, 0, 0, 0, datetime('now'), datetime('now', '+1 day'));\"")
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO preauth_keys (id, key, user_id, reusable, ephemeral, used, created_at, expiration) VALUES (2, 'preauth-key-client2', 1, 0, 0, 0, datetime('now'), datetime('now', '+1 day'));\"")

    # Wait for tailscaled to be running on both clients
    client1.wait_for_unit("tailscaled.service")
    client2.wait_for_unit("tailscaled.service")

    # Connect client1 to railscale (10 second timeout) with verbose output
    client1.execute("timeout 10 tailscale up --login-server=http://server:8080 --authkey=preauth-key-client1 --hostname=client1 2>&1 || true")

    # Show client1 daemon logs for debugging
    client1.execute("journalctl -u tailscaled.service --no-pager -n 50 || true")

    # Show server logs
    server.execute("journalctl -u railscale.service --no-pager -n 50 || true")

    # Check that both clients are connected
    client1.succeed("tailscale status")
    client2.succeed("tailscale status")

    # Get the tailscale IPs (should be instant after successful up)
    client1_ip = client1.succeed("tailscale ip -4").strip()
    client2_ip = client2.succeed("tailscale ip -4").strip()

    # Verify we got IPs
    assert client1_ip.startswith("100."), f"Expected 100.x.x.x IP for client1, got {client1_ip}"
    assert client2_ip.startswith("100."), f"Expected 100.x.x.x IP for client2, got {client2_ip}"

    # Print IPs for debugging
    print(f"Client1 Tailscale IP: {client1_ip}")
    print(f"Client2 Tailscale IP: {client2_ip}")

    # Test connectivity: client1 pings client2's tailscale IP (3 pings, 5 second timeout)
    client1.succeed(f"timeout 5 ping -c 3 {client2_ip}")

    # Test connectivity: client2 pings client1's tailscale IP (3 pings, 5 second timeout)
    client2.succeed(f"timeout 5 ping -c 3 {client1_ip}")

    # Check server logs to verify registrations
    server.succeed("journalctl -u railscale.service --no-pager | grep -i 'register'")

    print("SUCCESS: Both clients connected and can ping each other via Tailscale!")
  '';
}
