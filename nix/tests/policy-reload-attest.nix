# Policy Hot-Reload Test - attest/firecracker edition
#
# Same coverage as policy-reload.nix: SIGHUP reload, CLI reload, policy set
# Single VM, runs on firecracker
#
# Usage:
#   nix build .#policy-reload-attest -L
{
  pkgs,
  railscaleModule,
  attest,
  attestSrc,
}:
let
  common = import ./common.nix { inherit pkgs railscaleModule; };

  initialPolicy = builtins.toJSON {
    groups = {
      "group:engineering" = [ "alicja@example.com" ];
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

  policyPath = "/var/lib/railscale/policy.json";

  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "railscale-policy-reload";
  splitStore = true;

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        environment.systemPackages = [ pkgs.jq ];

        services.railscale = {
          enable = true;
          settings = {
            listen_addr = "0.0.0.0:8080";
            server_url = "http://server:8080";
          }
          // common.embeddedDerpSettings;
          policyFile = policyPath;
        };

        systemd.services.railscale.preStart = ''
          mkdir -p $(dirname ${policyPath})
          cat > ${policyPath} << 'EOF'
          ${initialPolicy}
          EOF
        '';

        systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
        boot.kernel.sysctl = common.serverSysctl;
        networking.firewall = common.serverFirewall;
      };
  };

  testScript = builtins.readFile ./policy-reload-attest.exs;
}
