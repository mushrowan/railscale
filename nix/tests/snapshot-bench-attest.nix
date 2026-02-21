# Snapshot restore benchmark
#
# Boots a railscale server, snapshots it after it's healthy,
# then restores from snapshot and verifies it's still working.
# The benchmark measures total time including snapshot create + restore.
#
# Usage:
#   nix build .#snapshot-bench-attest -L
{
  pkgs,
  railscale,
  attest,
  attestSrc,
}:
let
  common = import ./common.nix { inherit pkgs railscale; };
  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "railscale-snapshot-bench";
  splitStore = true;

  nodes = {
    server =
      { config, pkgs, ... }:
      {
        imports = [ common.railscaleModule ];

        # FC snapshot/restore requires kernel 6.1
        # (newer kernels triple-fault after restore)
        boot.kernelPackages = pkgs.linuxPackages_6_1;

        environment.systemPackages = [ pkgs.jq ];

        services.railscale = {
          enable = true;
          package = railscale;
          address = "0.0.0.0";
          port = 8080;
          settings = {
            server_url = "http://server:8080";
          } // common.embeddedDerpSettings;
        };

        networking.firewall = common.serverFirewall;
      };
  };

  testScript = ''
    start_all.()

    # cold boot and wait for service
    Attest.wait_for_unit(server, "railscale.service")
    Attest.wait_for_open_port(server, 8080)
    IO.puts("cold boot complete, service healthy")

    # snapshot
    t0 = System.monotonic_time(:millisecond)
    Attest.snapshot_create(server, "/tmp/snap")
    t1 = System.monotonic_time(:millisecond)
    IO.puts("snapshot created in #{t1 - t0}ms")

    # restore
    Attest.snapshot_restore(server, "/tmp/snap")
    t2 = System.monotonic_time(:millisecond)
    IO.puts("snapshot restored in #{t2 - t1}ms")

    # verify service still works after restore
    output = Attest.succeed(server, "systemctl is-active railscale.service")
    unless String.contains?(output, "active"), do: raise("service not active after restore")

    output = Attest.succeed(server, "curl -sf http://localhost:8080/health || echo unhealthy")
    IO.puts("health check after restore: #{String.trim(output)}")

    t3 = System.monotonic_time(:millisecond)
    IO.puts("")
    IO.puts("=== snapshot benchmark ===")
    IO.puts("snapshot create: #{t1 - t0}ms")
    IO.puts("snapshot restore: #{t2 - t1}ms")
    IO.puts("post-restore verify: #{t3 - t2}ms")
    IO.puts("total (create+restore+verify): #{t3 - t0}ms")
  '';
}
