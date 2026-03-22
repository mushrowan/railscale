# Headscale vs Railscale benchmark comparison
#
# Spins up both control servers in VMs with tailscale clients,
# measures registration + map poll latency for each.
#
# Usage:
#   nix run .#bench-comparison -L
{
  pkgs,
  railscaleModule,
  attest,
  attestSrc,
}:
let
  common = import ./common.nix { inherit pkgs railscaleModule; };
  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "bench-comparison";
  splitStore = true;
  memSize = 1024;

  nodes = {
    # railscale control server
    rs_server =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        services.railscale = {
          enable = true;
          openFirewall = true;

          policy = {
            grants = [
              {
                src = [ "*" ];
                dst = [ "*" ];
                ip = [ "*" ];
              }
            ];
          };

          settings = {
            listen_addr = "0.0.0.0:8080";
            server_url = "http://rs-server:8080";
            log_level = "warn";
            dns.nameservers.global = [ "1.1.1.1" ];
          };
        };

        environment.systemPackages = [ pkgs.jq ];
        boot.kernel.sysctl = common.serverSysctl;
        networking.firewall = common.serverFirewall;
      };

    # headscale control server
    hs_server =
      { config, pkgs, ... }:
      {
        services.headscale = {
          enable = true;
          settings = {
            listen_addr = "0.0.0.0:8080";
            server_url = "http://hs-server:8080";
            dns = {
              base_domain = "bench.test";
              nameservers.global = [ "1.1.1.1" ];
            };
            prefixes = {
              v4 = "100.64.0.0/10";
              v6 = "fd7a:115c:a1e0::/48";
            };
            derp = {
              urls = [ ];
              paths = [
                (pkgs.writeText "derp.yaml" ''
                  regions:
                    999:
                      regionid: 999
                      regioncode: bench
                      regionname: Bench Local
                      nodes:
                        - name: bench-derp
                          regionid: 999
                          hostname: hs-server
                          derpport: 443
                '')
              ];
              auto_update_enabled = false;
            };
          };
        };

        environment.systemPackages = [
          pkgs.headscale
          pkgs.jq
        ];

        networking.firewall.allowedTCPPorts = [ 8080 ];
      };

    # tailscale clients (one per server to keep VM count low)
    rs_client = common.mkClient { };
    hs_client = common.mkClient { };
  };

  testScript = builtins.readFile ./bench-comparison.exs;
}
