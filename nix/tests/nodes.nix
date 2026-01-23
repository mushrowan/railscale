# Node configurations for railscale NixOS VM tests
#
# Usage:
#   nodes = import ./nodes.nix { inherit pkgs railscale; };
{
  pkgs,
  railscale,
}:
let
  common = import ./common.nix { inherit pkgs railscale; };
in
{
  server =
    { config, pkgs, ... }:
    {
      imports = [ common.railscaleModule ];

      environment.systemPackages = [
        pkgs.sqlite
        pkgs.jq
        pkgs.curl # For REST API tests
      ];

      # Policy with groups for testing access control
      environment.etc."railscale/policy.json".text = builtins.toJSON {
        groups = {
          "group:engineering" = [ "alice@example.com" ];
          "group:admins" = [ "admin@example.com" ];
        };
        grants = [
          # All registered members can reach each other
          {
            src = [ "autogroup:member" ];
            dst = [ "autogroup:member" ];
            ip = [ "*" ];
          }
          # Engineering group can access tagged servers
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
          api = {
            enabled = true;
            rate_limit_enabled = true;
            # 200/min gives burst=33 (capped at 50), enough for tests
            # Rate limit test can still trigger 429 with rapid requests
            rate_limit_per_minute = 200;
          };
        }
        // common.embeddedDerpSettings;

        policyFile = "/etc/railscale/policy.json";
      };

      environment.variables.RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";
      systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
      networking.firewall = common.serverFirewall;
    };

  # Clients use shared configuration with python3 for STUN tests
  client1 = common.mkClient { extraPackages = [ pkgs.python3 ]; };
  client2 = common.mkClient { extraPackages = [ pkgs.python3 ]; };
}
