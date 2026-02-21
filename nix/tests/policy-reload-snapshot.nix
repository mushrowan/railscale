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
          } // common.embeddedDerpSettings;
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

  testScript = ''
    start_all.()

    # wait for server
    Attest.wait_for_unit(server, "railscale.service")
    Attest.wait_for_open_port(server, 8080)
    Process.sleep(1000)

    # -- initial policy check --
    IO.puts("--- get initial policy ---")
    output = Attest.succeed(server, "railscale policy get")
    policy = Jason.decode!(output)

    unless Map.has_key?(policy, "grants"), do: raise("policy should have grants")
    unless Map.has_key?(policy, "groups"), do: raise("policy should have groups")
    IO.puts("initial policy: #{length(policy["grants"])} grants, groups: #{inspect(Map.keys(policy["groups"]))}")

    # -- SIGHUP reload --
    IO.puts("--- SIGHUP policy reload ---")
    new_policy = Jason.encode!(%{
      "groups" => %{
        "group:engineering" => ["alice@example.com"],
        "group:admins" => ["admin@example.com"],
        "group:ops" => ["ops@example.com"]
      },
      "grants" => [
        %{"src" => ["autogroup:member"], "dst" => ["autogroup:member"], "ip" => ["*"]},
        %{"src" => ["group:engineering"], "dst" => ["tag:server"], "ip" => ["*"]},
        %{"src" => ["group:ops"], "dst" => ["tag:database"], "ip" => ["5432"]}
      ]
    })

    Attest.succeed(server, "echo '#{new_policy}' > /var/lib/railscale/policy.json")
    Attest.succeed(server, "systemctl reload railscale")
    Process.sleep(1000)

    output = Attest.succeed(server, "railscale policy get")
    policy = Jason.decode!(output)

    unless Map.has_key?(policy["groups"], "group:ops"), do: raise("ops group should be present")
    unless length(policy["grants"]) == 3, do: raise("expected 3 grants, got #{length(policy["grants"])}")
    IO.puts("SIGHUP reload ok - groups: #{inspect(Map.keys(policy["groups"]))}")

    # -- CLI reload --
    IO.puts("--- CLI policy reload ---")
    cli_policy = Jason.encode!(%{
      "groups" => %{
        "group:engineering" => ["alice@example.com"],
        "group:admins" => ["admin@example.com"],
        "group:ops" => ["ops@example.com"],
        "group:security" => ["security@example.com"]
      },
      "grants" => [
        %{"src" => ["autogroup:member"], "dst" => ["autogroup:member"], "ip" => ["*"]},
        %{"src" => ["group:engineering"], "dst" => ["tag:server"], "ip" => ["*"]},
        %{"src" => ["group:ops"], "dst" => ["tag:database"], "ip" => ["5432"]},
        %{"src" => ["group:security"], "dst" => ["*"], "ip" => ["22"]}
      ]
    })

    Attest.succeed(server, "echo '#{cli_policy}' > /var/lib/railscale/policy.json")
    output = Attest.succeed(server, "railscale policy reload")
    IO.puts("CLI reload: #{String.trim(output)}")

    output = Attest.succeed(server, "railscale policy get")
    policy = Jason.decode!(output)

    unless Map.has_key?(policy["groups"], "group:security"), do: raise("security group should be present")
    unless length(policy["grants"]) == 4, do: raise("expected 4 grants, got #{length(policy["grants"])}")
    IO.puts("CLI reload ok - 4 grants")

    # -- CLI policy set --
    IO.puts("--- CLI policy set ---")
    set_policy = Jason.encode!(%{
      "groups" => %{
        "group:developers" => ["dev@example.com"]
      },
      "grants" => [
        %{"src" => ["autogroup:member"], "dst" => ["autogroup:member"], "ip" => ["*"]},
        %{"src" => ["group:developers"], "dst" => ["tag:dev-server"], "ip" => ["*"]}
      ]
    })

    Attest.succeed(server, "echo '#{set_policy}' > /tmp/new-policy.json")
    output = Attest.succeed(server, "railscale policy set /tmp/new-policy.json")
    IO.puts("CLI set: #{String.trim(output)}")

    output = Attest.succeed(server, "railscale policy get")
    policy = Jason.decode!(output)

    unless Map.has_key?(policy["groups"], "group:developers"), do: raise("developers group should be present")
    if Map.has_key?(policy["groups"], "group:engineering"), do: raise("old groups should be gone")
    unless length(policy["grants"]) == 2, do: raise("expected 2 grants, got #{length(policy["grants"])}")
    IO.puts("CLI set ok - clean slate with 2 grants")

    # -- restore original --
    IO.puts("--- restore original policy ---")
    original = Jason.encode!(%{
      "groups" => %{
        "group:engineering" => ["alice@example.com"],
        "group:admins" => ["admin@example.com"]
      },
      "grants" => [
        %{"src" => ["autogroup:member"], "dst" => ["autogroup:member"], "ip" => ["*"]},
        %{"src" => ["group:engineering"], "dst" => ["tag:server"], "ip" => ["*"]}
      ]
    })

    Attest.succeed(server, "echo '#{original}' > /var/lib/railscale/policy.json")
    Attest.succeed(server, "railscale policy reload")

    output = Attest.succeed(server, "railscale policy get")
    policy = Jason.decode!(output)
    unless length(policy["grants"]) == 2, do: raise("expected 2 grants after restore")
    IO.puts("original policy restored")

    IO.puts("\\nall policy reload tests passed!")
  '';
}
