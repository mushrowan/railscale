# Policy Hot-Reload Test - pre-built snapshot edition
#
# Same as policy-reload-attest.nix but boots from a cached snapshot.
# the snapshot build (~10s) is cached by nix, so --rebuild only runs
# the test script from a ~128ms restore
#
# Usage:
#   nix build .#policy-reload-snapshot -L
{
  pkgs,
  railscale,
  attest,
  attestSrc,
}:
let
  common = import ./common.nix { inherit pkgs railscale; };

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

  policyPath = "/var/lib/railscale/policy.json";

  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "railscale-policy-reload-snap";
  splitStore = true;
  usePrebuiltSnapshots = true;

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        # FC snapshot/restore requires kernel 6.1
        boot.kernelPackages = pkgs.linuxPackages_6_1;

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
          policyFile = policyPath;
        };

        systemd.services.railscale.preStart = ''
          mkdir -p $(dirname ${policyPath})
          cat > ${policyPath} << 'EOF'
          ${initialPolicy}
          EOF
        '';

        systemd.services.railscale.environment.RAILSCALE_LOG_LEVEL = "debug";
        networking.firewall = common.serverFirewall;
      };
  };

  testScript = builtins.readFile ./policy-reload-attest.exs;
}
