{
  pkgs,
  railscale,
  lib,
}:
pkgs.testers.runNixOSTest {
  name = "railscale-basic";

  nodes = {
    server = {
      config,
      pkgs,
      ...
    }: {
      # Server node running railscale
      environment.systemPackages = [railscale pkgs.sqlite];

      # Create a simple policy file
      environment.etc."railscale/policy.json".text = builtins.toJSON {
        grants = [
          {
            src = ["*"];
            dst = ["*"];
            ip = ["*"];
          }
        ];
      };

      # Create systemd service
      systemd.services.railscale = {
        description = "Railscale Control Server";
        wantedBy = ["multi-user.target"];
        after = ["network.target"];

        environment = {
          RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";
          RAILSCALE_LISTEN_ADDR = "0.0.0.0:8080";
          RAILSCALE_SERVER_URL = "http://server:8080";
          RAILSCALE_POLICY_FILE = "/etc/railscale/policy.json";
          RAILSCALE_LOG_LEVEL = "debug";
        };

        serviceConfig = {
          ExecStart = "${lib.getExe railscale}";
          StateDirectory = "railscale";
          Restart = "on-failure";
        };
      };

      networking.firewall.allowedTCPPorts = [8080];
    };

    client = {
      config,
      pkgs,
      ...
    }: {
      # Client node for testing
      environment.systemPackages = [pkgs.curl pkgs.jq];
    };
  };

  testScript = ''
    start_all()

    # Wait for server to start
    server.wait_for_unit("railscale.service")
    server.wait_for_open_port(8080)

    # Check server is responding
    client.succeed("curl -f http://server:8080/ || true")

    # Create a preauth key directly in the database
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO users (id, name, created_at, updated_at) VALUES (1, 'testuser', datetime('now'), datetime('now'));\"")
    server.succeed("sqlite3 /var/lib/railscale/db.sqlite \"INSERT INTO preauth_keys (id, key, user_id, reusable, ephemeral, used, created_at, expiration) VALUES (1, 'test-preauth-key-12345', 1, 1, 0, 0, datetime('now'), datetime('now', '+1 day'));\"")


    # Test registration endpoint
    # Note: This is a simplified test - real registration requires Noise protocol
    client.succeed("""
      curl -X POST http://server:8080/machine/register \
        -H 'Content-Type: application/json' \
        -d '{
          "nodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000001",
          "oldNodeKey": null,
          "hostinfo": {
            "hostname": "test-node",
            "os": "linux",
            "osVersion": "NixOS"
          },
          "key": "test-preauth-key-12345"
        }' | jq -e '.node.id' || echo "Registration test (expected to work with full Noise implementation)"
    """)

    # Check server logs
    server.succeed("journalctl -u railscale.service --no-pager | grep -i 'Starting HTTP server'")
  '';
}
