# CLI Integration Test for railscale
#
# Tests all CLI commands: users, nodes, preauthkeys, apikeys
# also tests client connectivity via tailscale and ssh policy
#
# test modules are inlined via builtins.readfile for clean execution
{
  pkgs,
  railscale,
}:
let
  nodes = import ./nodes.nix { inherit pkgs railscale; };

  # read all python test modules
  helpers = builtins.readFile ./helpers.py;
  testServer = builtins.readFile ./test_server.py;
  testUsers = builtins.readFile ./test_users.py;
  testPreauthkeys = builtins.readFile ./test_preauthkeys.py;
  testApikeys = builtins.readFile ./test_apikeys.py;
  testNodes = builtins.readFile ./test_nodes.py;
  testKeysUsage = builtins.readFile ./test_keys_usage.py;
  testGroups = builtins.readFile ./test_groups.py;
  testRestApi = builtins.readFile ./test_rest_api.py;
  testSsh = builtins.readFile ./test_ssh.py;
in
pkgs.testers.runNixOSTest {
  name = "railscale-cli-integration";

  inherit nodes;

  testScript = ''
    # ==========================================================================
    # helpers (shared functions for all tests)
    # ==========================================================================
    ${helpers}

    # ==========================================================================
    # test execution
    # ==========================================================================
    start_all()

    # server startup and stun tests
    ${testServer}

    # user management cli tests (exports alice_id for later tests)
    ${testUsers}

    # preauth key management tests
    ${testPreauthkeys}

    # api key management tests
    ${testApikeys}

    # node management and connectivity tests
    ${testNodes}

    # key attribute and usage tests
    ${testKeysUsage}

    # group-based access control tests
    ${testGroups}

    # rest api tests
    ${testRestApi}

    # ssh policy tests
    ${testSsh}

    # ==========================================================================
    # done!
    # ==========================================================================
    print("\n" + "=" * 70)
    print("ALL TESTS PASSED!")
    print("=" * 70)
  '';
}
