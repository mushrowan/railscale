# Node configurations for railscale NixOS VM tests
#
# Usage:
#   nodes = import ./nodes.nix { inherit pkgs railscale; };
{
  pkgs,
  railscale,
}:
let
  commonClientFlags = [ "--verbose=5" ];
  railscaleModule = import ../module.nix;
in
{
  server =
    { config, pkgs, ... }:
    {
      imports = [ railscaleModule ];

      environment.systemPackages = [
        pkgs.sqlite
        pkgs.jq
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

          derp.embedded_derp = {
            enabled = true;
            advertise_host = "192.168.1.3";
            advertise_port = 3340;
          };
        };

        policyFile = "/etc/railscale/policy.json";
      };

      environment.variables.RAILSCALE_DATABASE_URL = "sqlite:///var/lib/railscale/db.sqlite";
      systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
      networking.firewall.allowedTCPPorts = [ 8080 ];
      networking.firewall.allowedUDPPorts = [ 3478 ]; # STUN
    };

  client1 =
    { config, pkgs, ... }:
    {
      services.tailscale = {
        enable = true;
        extraDaemonFlags = commonClientFlags;
      };

      systemd.services.tailscaled.environment = {
        TS_NO_LOGS_NO_SUPPORT = "1";
      };

      environment.systemPackages = [
        pkgs.tailscale
        pkgs.python3 # For STUN test
      ];
    };

  client2 =
    { config, pkgs, ... }:
    {
      services.tailscale = {
        enable = true;
        extraDaemonFlags = commonClientFlags;
      };

      systemd.services.tailscaled.environment = {
        TS_NO_LOGS_NO_SUPPORT = "1";
      };

      environment.systemPackages = [
        pkgs.tailscale
        pkgs.python3 # For STUN test
      ];
    };
}
