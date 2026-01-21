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
  common = import ./common.nix { inherit pkgs railscale; };
  helpers = ./helpers.py;
  testScript = ./policy-reload.py;

  # Initial policy - copied to writable location at startup
  initialPolicy = builtins.toJSON {
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

  # Writable policy path (not in /etc which is managed by NixOS)
  policyPath = "/var/lib/railscale/policy.json";
in
pkgs.testers.runNixOSTest {
  name = "railscale-policy-reload";

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        environment.systemPackages = [ pkgs.jq ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;

          settings = {
            server_url = "http://server:8080";
          }
          // common.embeddedDerpSettings;

          # Use writable path for policy (not environment.etc)
          policyFile = policyPath;
        };

        # Write initial policy before railscale starts
        systemd.services.railscale.preStart = ''
          mkdir -p $(dirname ${policyPath})
          cat > ${policyPath} << 'EOF'
          ${initialPolicy}
          EOF
        '';

        systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
        networking.firewall = common.serverFirewall;
      };

    # Use shared client configuration (needed for future policy effect tests)
    client1 = common.mkClient { };
    client2 = common.mkClient { };
  };

  testScript = ''
    # Load helpers
    exec(open("${helpers}").read())

    # Run test script
    exec(open("${testScript}").read())
  '';
}
