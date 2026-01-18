# Policy Hot-Reload Test for railscale
#
# Tests:
# - SIGHUP-based policy reload via systemctl reload
# - CLI-based policy reload via `railscale policy reload`
# - Policy get/set via CLI
{
  pkgs,
  railscale,
}:
let
  # Use a minimal node setup (just server, no clients needed)
  railscaleModule = import ../module.nix;
  helpers = ./helpers.py;
  testScript = ./policy-reload.py;
in
pkgs.testers.runNixOSTest {
  name = "railscale-policy-reload";

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ railscaleModule ];

        environment.systemPackages = [ pkgs.jq ];

        # Initial policy
        environment.etc."railscale/policy.json".text = builtins.toJSON {
          groups = {
            "group:engineering" = [ "alice@example.com" ];
            "group:admins" = [ "admin@example.com" ];
          };
          grants = [
            {
              src = [ "autogroup:member" ];
              dst = [ "autogroup:member" ];
              ip = [ "*" ];
            }
            {
              src = [ "group:engineering" ];
              dst = [ "tag:server" ];
              ip = [ "*" ];
            }
          ];
        };

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;

          settings = {
            server_url = "http://server:8080";
          };

          policyFile = "/etc/railscale/policy.json";
        };

        systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

    # Dummy clients for wait_for_network helper
    client1 =
      { config, pkgs, ... }:
      {
        services.tailscale.enable = true;
        environment.systemPackages = [ pkgs.tailscale ];
      };

    client2 =
      { config, pkgs, ... }:
      {
        services.tailscale.enable = true;
        environment.systemPackages = [ pkgs.tailscale ];
      };
  };

  testScript = ''
    # Load helpers
    exec(open("${helpers}").read())

    # Run test script
    exec(open("${testScript}").read())
  '';
}
