# CLI Integration Test - attest/firecracker edition
#
# Full port of cli-integration.nix: users, preauthkeys, apikeys, nodes,
# taildrop, key usage, groups, REST API, SSH policy, tailnet lock
#
# 3 VMs (server, client1, client2) with networking
#
# Usage:
#   nix build .#cli-integration-attest -L
{
  pkgs,
  railscale,
  attest,
  attestSrc,
}:
let
  nodes = import ./nodes.nix { inherit pkgs railscale; };
  makeTest = import "${attestSrc}/nix/firecracker/make-test.nix";
in
makeTest {
  inherit pkgs attest;
  name = "railscale-cli";
  splitStore = true;
  memSize = 512;

  nodes = {
    inherit (nodes) server client1 client2;
  };

  testScript = builtins.readFile ./cli-integration-attest.exs;
}
