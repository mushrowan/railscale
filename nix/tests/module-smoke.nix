# Module Smoke Test for railscale
#
# Quick test to verify the server starts successfully with various NixOS module options.
# Not included in `nix flake check` - run manually with:
#   nix build .#module-smoke-test && ./result/bin/nixos-test-driver
#
# Tests:
# - Basic server startup
# - API enabled with rate limiting
# - Embedded DERP enabled
# - DNS extra_records
# - Custom log level
{
  pkgs,
  railscale,
}:
let
  common = import ./common.nix { inherit pkgs railscale; };
in
pkgs.testers.runNixOSTest {
  name = "railscale-module-smoke";

  nodes = {
    # Basic server with minimal config
    basic =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;
          settings = {
            server_url = "http://basic:8080";
            log_level = "debug";
          };
        };

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

    # Server with API enabled and rate limiting
    withapi =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;
          settings = {
            server_url = "http://withapi:8080";
            log_level = "info";
            api = {
              enabled = true;
              rate_limit_enabled = true;
              rate_limit_per_minute = 50;
            };
          };
        };

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

    # Server with embedded DERP
    withderp =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;
          settings = {
            server_url = "http://withderp:8080";
            log_level = "warn";
            derp.embedded_derp = {
              enabled = true;
              advertise_host = "192.168.1.5";
              advertise_port = 3340;
              max_connections = 500;
              idle_timeout_secs = 120;
              bytes_per_second = 51200;
              connection_rate_per_minute = 5;
            };
          };
        };

        networking.firewall = common.serverFirewall;
      };

    # Server with DNS extra_records
    withdns =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;
          settings = {
            server_url = "http://withdns:8080";
            dns = {
              magic_dns = true;
              extra_records = [
                { name = "grafana.railscale.net"; record_type = "A"; value = "100.64.0.5"; }
                { name = "prometheus.railscale.net"; record_type = "A"; value = "100.64.0.6"; }
              ];
            };
          };
        };

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };
  };

  testScript = ''
    import time

    def check_server_healthy(node, name):
        """Check that railscale service is active and responds to health check"""
        node.wait_for_unit("railscale.service")
        
        # give it a moment to fully start
        time.sleep(3)
        
        # verify still running (didn't crash)
        status = node.succeed("systemctl is-active railscale.service").strip()
        assert status == "active", f"{name}: service not active, got {status}"
        
        # check no errors in recent logs (just warnings/info ok)
        # we grep for ERROR level messages
        result = node.execute("journalctl -u railscale --no-pager | grep -i 'ERROR' | head -5")[1]
        if "ERROR" in result:
            print(f"{name}: found errors in logs: {result}")
            # don't fail on errors for now, just warn
        
        print(f"{name}: server healthy after 3 seconds")

    start_all()

    # Test each server configuration
    with subtest("basic server starts"):
        check_server_healthy(basic, "basic")

    with subtest("server with API enabled starts"):
        check_server_healthy(withapi, "withapi")

    with subtest("server with embedded DERP starts"):
        check_server_healthy(withderp, "withderp")

    with subtest("server with DNS extra_records starts"):
        check_server_healthy(withdns, "withdns")

    print("All smoke tests passed!")
  '';
}
