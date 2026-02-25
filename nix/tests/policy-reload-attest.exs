start_all.()

# wait for server
Attest.wait_for_unit(server, "railscale.service")
Attest.wait_for_open_port(server, 8080)
Attest.wait_until_succeeds(server, "curl -sf http://localhost:8080/health")

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
    "group:engineering" => ["alicja@example.com"],
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

Attest.wait_until_succeeds(server,
  "railscale policy get | grep -q group:ops")

output = Attest.succeed(server, "railscale policy get")
policy = Jason.decode!(output)

unless Map.has_key?(policy["groups"], "group:ops"), do: raise("ops group should be present")
unless length(policy["grants"]) == 3, do: raise("expected 3 grants, got #{length(policy["grants"])}")
IO.puts("SIGHUP reload ok - groups: #{inspect(Map.keys(policy["groups"]))}")

# -- CLI reload --
IO.puts("--- CLI policy reload ---")
cli_policy = Jason.encode!(%{
  "groups" => %{
    "group:engineering" => ["alicja@example.com"],
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
    "group:engineering" => ["alicja@example.com"],
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

IO.puts("\nall policy reload tests passed!")
