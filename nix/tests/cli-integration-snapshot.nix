# CLI Integration Test - pre-built snapshot edition
#
# Same as cli-integration-attest.nix but boots from cached snapshots.
# the snapshot build is cached by nix, --rebuild only runs the test
#
# Usage:
#   nix build .#cli-integration-snapshot -L
{
  pkgs,
  railscale,
  attest,
  attestSrc,
}:
let
  nodes = import ./nodes.nix { inherit pkgs railscale; };
  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";

  # add kernel 6.1 to each node for snapshot compatibility
  withKernel61 =
    nodeModule:
    {
      config,
      pkgs,
      ...
    }@args:
    {
      imports = [ (nodeModule args) ];
      boot.kernelPackages = pkgs.linuxPackages_6_1;
    };
in
makeTest {
  inherit pkgs attest;
  name = "railscale-cli-snap";
  splitStore = true;
  usePrebuiltSnapshots = true;
  memSize = 512;

  nodes = {
    server = withKernel61 nodes.server;
    client1 = withKernel61 nodes.client1;
    client2 = withKernel61 nodes.client2;
  };

  testScript = builtins.readFile ./cli-integration-attest.exs;
}
