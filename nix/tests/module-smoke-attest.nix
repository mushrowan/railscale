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
        } // extraSettings;
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

    withderp = mkServerNode "withderp" ({
      log_level = "warn";
    } // common.embeddedDerpSettings);

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

  testScript = ''
    defmodule Check do
      def server_healthy(machine, name) do
        Attest.wait_for_unit(machine, "railscale.service")
        Attest.wait_for_open_port(machine, 8080)

        status = Attest.succeed(machine, "systemctl is-active railscale.service")

        unless String.contains?(status, "active") do
          raise "#{name}: service not active, got #{inspect(status)}"
        end

        # check for errors in logs (warn only, don't fail)
        {code, output} = Attest.Machine.execute(machine, "journalctl -u railscale --no-pager | grep -i ERROR | head -5")

        if code == 0 and String.contains?(output, "ERROR") do
          IO.puts("#{name}: found errors in logs: #{output}")
        end

        IO.puts("#{name}: server healthy")
      end
    end

    start_all.()

    machines = [
      {basic, "basic", "basic server starts"},
      {withapi, "withapi", "server with API enabled starts"},
      {withderp, "withderp", "server with embedded DERP starts"},
      {withdns, "withdns", "server with DNS extra_records starts"}
    ]

    Attest.wait_all(machines, fn {machine, name, label} ->
      IO.puts("--- #{label} ---")
      Check.server_healthy(machine, name)
    end)

    IO.puts("all smoke tests passed!")
  '';
}
