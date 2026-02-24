# Module Smoke Test for railscale - attest/firecracker edition
#
# Same coverage as module-smoke.nix but runs on firecracker via attest
# instead of QEMU via the python driver. ~2x faster boot times
#
# Usage:
#   nix build .#module-smoke-attest -L
{
  pkgs,
  railscale,
  # the attest escript package (from nixos-test-ng flake)
  attest,
  # path to the attest source tree (for nix/firecracker/make-test.nix)
  attestSrc,
}:
let
  common = import ./common.nix { inherit pkgs railscale; };

  mkServerNode =
    name: extraSettings:
    {
      config,
      pkgs,
      ...
    }:
    {
      imports = [ common.railscaleModule ];

      services.railscale = {
        enable = true;
        package = railscale;
        address = "0.0.0.0";
        port = 8080;
        settings = {
          server_url = "http://${name}:8080";
        }
        // extraSettings;
      };

      networking.firewall = common.serverFirewall;
    };

  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "railscale-smoke";
  splitStore = true;

  nodes = {
    basic = mkServerNode "basic" {
      log_level = "debug";
    };

    withapi = mkServerNode "withapi" {
      log_level = "info";
      api = {
        enabled = true;
        rate_limit_enabled = true;
        rate_limit_per_minute = 50;
      };
    };

    withderp = mkServerNode "withderp" (
      {
        log_level = "warn";
      }
      // common.embeddedDerpSettings
    );

    withdns = mkServerNode "withdns" {
      dns = {
        magic_dns = true;
        extra_records = [
          {
            name = "grafana.railscale.net";
            record_type = "A";
            value = "100.64.0.5";
          }
          {
            name = "prometheus.railscale.net";
            record_type = "A";
            value = "100.64.0.6";
          }
        ];
      };
    };
  };

  testScript = builtins.readFile ./module-smoke-attest.exs;
}
