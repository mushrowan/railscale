# CLI Integration Test for railscale
#
# Tests all CLI commands: users, nodes, preauthkeys, apikeys
# Also tests client connectivity via tailscale
{
  pkgs,
  railscale,
}:
let
  nodes = import ./nodes.nix { inherit pkgs railscale; };
  helpers = ./helpers.py;
  testScript = ./cli-integration.py;
in
pkgs.testers.runNixOSTest {
  name = "railscale-cli-integration";

  inherit nodes;

  testScript = ''
    # Load helpers
    exec(open("${helpers}").read())

    # Run test script
    exec(open("${testScript}").read())
  '';
}
