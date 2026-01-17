{
  pkgs,
  railscale,
}:
pkgs.testers.runNixOSTest {
  name = "railscale-tailscale-integration";

  nodes =
    let
      commonClientFlags = [ "--verbose=5" ];
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

          systemd.services.railscale = {
            description = "Railscale Control Server";
            wantedBy = [ "multi-user.target" ];
            after = [ "network.target" ];

            environment = {
              RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";
              RAILSCALE_LISTEN_ADDR = "0.0.0.0:8080";
              RAILSCALE_SERVER_URL = "http://server:8080";
              RAILSCALE_POLICY_FILE = "/etc/railscale/policy.json";
              RAILSCALE_LOG_LEVEL = "trace";
              # Enable embedded DERP relay for peer connectivity in isolated VMs
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

          # Disable log uploads to avoid DNS lookups for log.tailscale.com
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

          # Disable log uploads to avoid DNS lookups for log.tailscale.com
          systemd.services.tailscaled.environment = {
            TS_NO_LOGS_NO_SUPPORT = "1";
          };

          environment.systemPackages = [ pkgs.tailscale ];
        };
    };

  testScript = ''
    start_all()

    # Wait for railscale server to start
    server.wait_for_unit("railscale.service")
    server.wait_for_open_port(8080)
    server.wait_for_open_port(3340)  # DERP relay port

    # Create a user and two preauth keys
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO users (id, name, created_at, updated_at) VALUES (1, 'testuser', datetime('now'), datetime('now'));\"")
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO preauth_keys (id, key, user_id, reusable, ephemeral, used, created_at, expiration) VALUES (1, 'preauth-key-client1', 1, 0, 0, 0, datetime('now'), datetime('now', '+1 day'));\"")
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO preauth_keys (id, key, user_id, reusable, ephemeral, used, created_at, expiration) VALUES (2, 'preauth-key-client2', 1, 0, 0, 0, datetime('now'), datetime('now', '+1 day'));\"")

    # Wait for tailscaled to be running on both clients
    client1.wait_for_unit("tailscaled.service")
    client2.wait_for_unit("tailscaled.service")

    # Wait for DHCP to complete on all machines to prevent link changes during registration
    # The eth0 interface gets DHCP, which can cause Tailscale to detect a "major link change"
    # and close connections mid-registration
    server.wait_for_unit("dhcpcd.service")
    client1.wait_for_unit("dhcpcd.service")
    client2.wait_for_unit("dhcpcd.service")

    # Use the server's private IP (192.168.1.3) instead of hostname "server"
    # This is necessary because Tailscale's control client only recognizes IPs, loopback,
    # or "localhost" as private hosts. For non-private hosts, it falls back to port 443
    # after a connection failure, which we don't have open.
    # See: tailscale/control/ts2021/client.go lines 129-151

    # Connect client1 to railscale (10 second timeout) with verbose output
    client1.execute("timeout 10 tailscale up --login-server=http://192.168.1.3:8080 --authkey=preauth-key-client1 --hostname=client1 2>&1 || true")
    client2.execute("timeout 10 tailscale up --login-server=http://192.168.1.3:8080 --authkey=preauth-key-client2 --hostname=client2 2>&1 || true")

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

    # Show netcheck/DERP status
    client1.execute("tailscale netcheck 2>&1 || true")
    client1.execute("tailscale status --json | head -100 || true")

    # Test connectivity: client1 pings client2's tailscale IP (3 pings, 10 second timeout)
    # Increased timeout to allow DERP relay connection to establish
    client1.succeed(f"timeout 10 ping -c 3 {client2_ip}")

    # Test connectivity: client2 pings client1's tailscale IP (3 pings, 10 second timeout)
    client2.succeed(f"timeout 10 ping -c 3 {client1_ip}")

    # Check server logs to verify registrations
    server.succeed("journalctl -u railscale.service --no-pager | grep -i 'register'")

    print("SUCCESS: Both clients connected and can ping each other via Tailscale!")
  '';
}
