# railscale CLI integration test - elixir/attest port
#
# tests: users, preauthkeys, apikeys, nodes, taildrop, key usage,
# groups, REST API, SSH policy, tailnet lock

# -- helpers --

defmodule H do
  @server_url "http://192.168.1.3:8080"

  def railscale(server, cmd), do: Attest.succeed(server, "railscale #{cmd}")

  def railscale_json(server, cmd) do
    server |> railscale("#{cmd} -o json") |> Jason.decode!()
  end

  def extract_key(output) do
    output
    |> String.split("\n")
    |> Enum.find_value(fn line ->
      if String.contains?(line, "Key:") do
        line |> String.split("Key:") |> List.last() |> String.trim()
      end
    end) || raise "could not find Key in output: #{output}"
  end

  def connect_client(client, key, hostname, opts \\ []) do
    expect_success = Keyword.get(opts, :expect_success, true)
    ssh = if Keyword.get(opts, :ssh, false), do: " --ssh", else: ""

    Attest.Machine.execute(client,
      "timeout 15 tailscale up --login-server=#{@server_url}" <>
      " --authkey=#{key} --hostname=#{hostname}#{ssh} 2>&1 || true"
    )

    Process.sleep(2000)
    if expect_success, do: Process.sleep(3000)
  end

  def get_client_ip(client) do
    {code, output} = Attest.Machine.execute(client, "tailscale ip -4 2>&1")
    ip = String.trim(output)
    if code == 0 and String.starts_with?(ip, "100."), do: ip, else: nil
  end

  def disconnect_client(client) do
    Attest.Machine.execute(client, "tailscale logout 2>&1 || true")
    Process.sleep(2000)
  end

  def reset_client(client) do
    Attest.Machine.execute(client, "tailscale logout 2>&1 || true")
    Attest.Machine.execute(client, "systemctl stop tailscaled")
    Attest.Machine.execute(client, "rm -rf /var/lib/tailscale/*")
    Attest.Machine.execute(client, "systemctl start tailscaled")
    Attest.wait_for_unit(client, "tailscaled.service")
    Process.sleep(1000)
  end

  def wait_for_server(server) do
    Attest.wait_for_unit(server, "railscale.service")
    Attest.wait_for_open_port(server, 8080)
    Attest.wait_for_open_port(server, 3340)
    Process.sleep(1000)
  end

  def wait_for_network(server, client1, client2) do
    Attest.wait_for_unit(server, "multi-user.target")
    Attest.wait_for_unit(client1, "multi-user.target")
    Attest.wait_for_unit(client2, "multi-user.target")
    Attest.wait_for_unit(client1, "tailscaled.service")
    Attest.wait_for_unit(client2, "tailscaled.service")
    Process.sleep(3000)
  end

  def create_user_and_get_id(server, email, display_name \\ nil) do
    if display_name do
      railscale(server, "users create #{email} --display-name '#{display_name}'")
    else
      railscale(server, "users create #{email}")
    end

    server
    |> railscale_json("users list")
    |> Enum.find(fn u -> u["email"] == email end)
    |> Map.fetch!("id")
  end

  def create_preauth_key(server, user_id, opts \\ []) do
    args = "-u #{user_id}"
    args = if Keyword.get(opts, :reusable, false), do: args <> " --reusable", else: args
    args = if Keyword.get(opts, :ephemeral, false), do: args <> " --ephemeral", else: args
    days = Keyword.get(opts, :expiration_days, 1)
    args = if days > 0, do: args <> " --expiration-days #{days}", else: args <> " --expiration-days 0"
    args = case Keyword.get(opts, :tags) do
      nil -> args
      tags -> args <> " --tags #{tags}"
    end

    server |> railscale("preauthkeys create #{args}") |> extract_key()
  end

  def get_node_by_name(server, name) do
    server
    |> railscale_json("nodes list")
    |> Enum.find(fn n -> n["given_name"] == name end)
  end

  # REST API helpers
  def api_get(server, path, api_key) do
    cmd = "curl -s -H 'Authorization: Bearer #{api_key}' '#{@server_url}#{path}'"
    Attest.succeed(server, cmd) |> try_json()
  end

  defp try_json(output) do
    trimmed = String.trim(output)
    if trimmed == "" do
      %{}
    else
      case Jason.decode(trimmed) do
        {:ok, val} -> val
        {:error, _} -> %{"_raw" => trimmed}
      end
    end
  end

  def api_post(server, path, api_key, data \\ nil) do
    cmd = if data do
      json = Jason.encode!(data)
      "curl -s -X POST -H 'Authorization: Bearer #{api_key}' -H 'Content-Type: application/json' -d '#{json}' '#{@server_url}#{path}'"
    else
      "curl -s -X POST -H 'Authorization: Bearer #{api_key}' '#{@server_url}#{path}'"
    end
    Attest.succeed(server, cmd) |> try_json()
  end

  def api_put(server, path, api_key, data) do
    json = Jason.encode!(data)
    cmd = "curl -s -X PUT -H 'Authorization: Bearer #{api_key}' -H 'Content-Type: application/json' -d '#{json}' '#{@server_url}#{path}'"
    Attest.succeed(server, cmd) |> try_json()
  end

  def api_delete(server, path, api_key) do
    cmd = "curl -s -X DELETE -H 'Authorization: Bearer #{api_key}' '#{@server_url}#{path}'"
    Attest.succeed(server, cmd) |> try_json()
  end

  def api_status(server, path, method \\ "GET", api_key \\ nil) do
    auth = if api_key, do: "-H 'Authorization: Bearer #{api_key}'", else: ""
    cmd = "curl -s -o /dev/null -w '%{http_code}' -X #{method} #{auth} '#{@server_url}#{path}'"
    Attest.succeed(server, cmd) |> String.trim() |> String.to_integer()
  end

  def create_api_key_for_user(server, user_id, name \\ "test-api-key") do
    server |> railscale("apikeys create -u #{user_id} --name '#{name}'") |> extract_key()
  end

  def try_ssh(src, dst_ip, user, timeout \\ 10) do
    opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
    cmd = "timeout #{timeout} ssh #{opts} #{user}@#{dst_ip} 'echo SUCCESS' 2>&1"
    {code, output} = Attest.Machine.execute(src, cmd)
    {code == 0 and String.contains?(output, "SUCCESS"), output}
  end
end

# ==========================================================================
# PHASE 1: Server Startup
# ==========================================================================
start_all.()

IO.puts("--- server startup ---")
H.wait_for_server(server)
H.wait_for_network(server, client1, client2)
IO.puts("server started")

# STUN test
IO.puts("--- STUN test ---")
{_, netcheck} = Attest.Machine.execute(client1, "tailscale netcheck --format=json 2>&1 || true")
IO.puts("netcheck: #{String.slice(netcheck, 0, 200)}")

# ==========================================================================
# PHASE 2: User Management
# ==========================================================================
IO.puts("--- user management ---")

output = H.railscale(server, "users create alice@example.com --display-name 'Alice Smith'")
unless String.contains?(output, "Created user"), do: raise("create user failed: #{output}")

users = H.railscale_json(server, "users list")
unless length(users) == 1, do: raise("expected 1 user, got #{length(users)}")
unless hd(users)["email"] == "alice@example.com", do: raise("wrong email")

H.railscale(server, "users create bob@example.com")
users = H.railscale_json(server, "users list")
unless length(users) == 2, do: raise("expected 2 users")

bob = Enum.find(users, fn u -> u["email"] == "bob@example.com" end)
bob_id = bob["id"]
output = H.railscale(server, "users rename #{bob_id} robert@example.com")
unless String.contains?(output, "Renamed"), do: raise("rename failed")

users = H.railscale_json(server, "users list")
emails = Enum.map(users, & &1["email"])
unless "robert@example.com" in emails, do: raise("robert not found")

robert = Enum.find(users, fn u -> u["email"] == "robert@example.com" end)
output = H.railscale(server, "users delete #{robert["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete failed")

users = H.railscale_json(server, "users list")
unless length(users) == 1, do: raise("expected 1 user after delete")

alice_id = hd(users)["id"]
IO.puts("alice id: #{alice_id}")

# ==========================================================================
# PHASE 3: Preauth Keys
# ==========================================================================
IO.puts("--- preauth keys ---")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --expiration-days 1")
unless String.contains?(output, "Created preauth key"), do: raise("create pak failed")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --reusable --expiration-days 1")
unless String.contains?(output, "Reusable:  true"), do: raise("reusable flag missing")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --tags server,web --expiration-days 1")
unless String.contains?(output, "server"), do: raise("tags missing")

keys = H.railscale_json(server, "preauthkeys list")
key_id = hd(keys)["id"]
output = H.railscale(server, "preauthkeys expire #{key_id}")
unless String.contains?(output, "Expired"), do: raise("expire failed")

IO.puts("preauth keys ok")

# ==========================================================================
# PHASE 3.5: API Keys
# ==========================================================================
IO.puts("--- api keys ---")

output = H.railscale(server, "apikeys create -u #{alice_id} --name 'Test Key' --expiration-days 30")
unless String.contains?(output, "rsapi_"), do: raise("api key missing prefix")

output = H.railscale(server, "apikeys create -u #{alice_id} --name 'Perm Key' --expiration-days 0")
unless String.contains?(String.downcase(output), "never"), do: raise("no-expiry missing")

keys = H.railscale_json(server, "apikeys list")
key_id = hd(keys)["id"]
output = H.railscale(server, "apikeys expire #{key_id}")
unless String.contains?(output, "Expired"), do: raise("expire api key failed")

IO.puts("api keys ok")

# ==========================================================================
# PHASE 4: Client Connection + Node Management
# ==========================================================================
IO.puts("--- nodes ---")

key1 = H.create_preauth_key(server, alice_id)
key2 = H.create_preauth_key(server, alice_id)
H.connect_client(client1, key1, "client1")
H.connect_client(client2, key2, "client2")

client1_ip = H.get_client_ip(client1)
client2_ip = H.get_client_ip(client2)
unless client1_ip, do: raise("client1 no IP")
unless client2_ip, do: raise("client2 no IP")
IO.puts("client1=#{client1_ip} client2=#{client2_ip}")

# ping
Attest.succeed(client1, "timeout 15 ping -c 3 #{client2_ip}")
Attest.succeed(client2, "timeout 15 ping -c 3 #{client1_ip}")
IO.puts("clients can ping")

# list nodes
nodes_list = H.railscale_json(server, "nodes list")
unless length(nodes_list) == 2, do: raise("expected 2 nodes, got #{length(nodes_list)}")
hostnames = Enum.map(nodes_list, & &1["given_name"])
unless "client1" in hostnames and "client2" in hostnames, do: raise("missing hostnames")

# node operations
node1 = Enum.find(nodes_list, fn n -> n["given_name"] == "client1" end)
node1_id = node1["id"]

output = H.railscale(server, "nodes show #{node1_id}")
unless String.contains?(output, "client1"), do: raise("show failed")

output = H.railscale(server, "nodes rename #{node1_id} client1-renamed")
unless String.contains?(output, "Renamed"), do: raise("rename failed")
H.railscale(server, "nodes rename #{node1_id} client1")

output = H.railscale(server, "nodes tags add #{node1_id} server,web")
unless String.contains?(output, "tag:server"), do: raise("add tags failed")

output = H.railscale(server, "nodes tags remove #{node1_id} web")
unless String.contains?(output, "tag:server"), do: raise("remove tag failed")

output = H.railscale(server, "nodes tags set #{node1_id} production,critical")
unless String.contains?(output, "tag:production"), do: raise("set tags failed")

output = H.railscale(server, "nodes routes approve #{node1_id} 10.0.0.0/8,192.168.0.0/16")
unless String.contains?(output, "10.0.0.0/8"), do: raise("approve routes failed")

output = H.railscale(server, "nodes routes unapprove #{node1_id} 192.168.0.0/16")
unless String.contains?(output, "10.0.0.0/8"), do: raise("unapprove failed")

output = H.railscale(server, "nodes expire #{node1_id}")
unless String.contains?(output, "Expired"), do: raise("expire node failed")

# delete node
node2 = Enum.find(nodes_list, fn n -> n["given_name"] == "client2" end)
output = H.railscale(server, "nodes delete #{node2["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete node failed")

nodes_list = H.railscale_json(server, "nodes list")
ids = Enum.map(nodes_list, & &1["id"])
if node2["id"] in ids, do: raise("deleted node still present")

IO.puts("nodes ok")

# ==========================================================================
# PHASE 5: Taildrop
# ==========================================================================
IO.puts("--- taildrop ---")

H.reset_client(client1)
H.reset_client(client2)
key1 = H.create_preauth_key(server, alice_id)
key2 = H.create_preauth_key(server, alice_id)
H.connect_client(client1, key1, "client1")
H.connect_client(client2, key2, "client2")
Process.sleep(5000)

# file targets
{c1, t1} = Attest.Machine.execute(client1, "tailscale file cp --targets 2>&1")
{c2, t2} = Attest.Machine.execute(client2, "tailscale file cp --targets 2>&1")
unless c1 == 0 and String.contains?(t1, "client2"), do: raise("client1 can't see client2 targets: #{t1}")
unless c2 == 0 and String.contains?(t2, "client1"), do: raise("client2 can't see client1 targets: #{t2}")

# send file
Attest.succeed(client1, "echo 'hello from taildrop' > /tmp/td.txt")
Attest.succeed(client1, "tailscale file cp /tmp/td.txt client2: 2>&1")
Process.sleep(2000)
Attest.succeed(client2, "mkdir -p /tmp/recv")
Attest.succeed(client2, "tailscale file get /tmp/recv/ 2>&1")
received = Attest.succeed(client2, "cat /tmp/recv/td.txt") |> String.trim()
unless received == "hello from taildrop", do: raise("taildrop content mismatch: #{received}")

# bidirectional
Attest.succeed(client2, "echo 'reply' > /tmp/reply.txt")
Attest.succeed(client2, "tailscale file cp /tmp/reply.txt client1: 2>&1")
Process.sleep(2000)
Attest.succeed(client1, "mkdir -p /tmp/recv")
Attest.succeed(client1, "tailscale file get /tmp/recv/ 2>&1")
reply = Attest.succeed(client1, "cat /tmp/recv/reply.txt") |> String.trim()
unless reply == "reply", do: raise("bidirectional taildrop failed")

IO.puts("taildrop ok")

# ==========================================================================
# PHASE 6: Key Usage Tests
# ==========================================================================
IO.puts("--- key usage ---")

# non-reusable key used twice
single_key = H.create_preauth_key(server, alice_id)
H.reset_client(client2)
H.connect_client(client2, single_key, "single-1")
unless H.get_client_ip(client2), do: raise("first use should work")
H.reset_client(client2)
H.connect_client(client2, single_key, "single-2", expect_success: false)
if H.get_client_ip(client2), do: raise("second use should fail")
IO.puts("non-reusable key enforced")

# reusable key
reusable_key = H.create_preauth_key(server, alice_id, reusable: true)
for i <- 1..3 do
  H.reset_client(client2)
  H.connect_client(client2, reusable_key, "reuse-#{i}")
  unless H.get_client_ip(client2), do: raise("reusable use #{i} failed")
end
IO.puts("reusable key ok")

# expired key
exp_key = H.create_preauth_key(server, alice_id)
keys = H.railscale_json(server, "preauthkeys list")
the_key = Enum.find(keys, fn k -> String.starts_with?(exp_key, k["key"]) end)
H.railscale(server, "preauthkeys expire #{the_key["id"]}")
H.reset_client(client2)
H.connect_client(client2, exp_key, "expired-test", expect_success: false)
if H.get_client_ip(client2), do: raise("expired key should fail")
IO.puts("expired key rejected")

# deleted node gets new ID
fresh_key = H.create_preauth_key(server, alice_id)
H.reset_client(client2)
H.connect_client(client2, fresh_key, "del-test")
old_node = H.get_node_by_name(server, "del-test")
old_id = old_node["id"]
H.railscale(server, "nodes delete #{old_id}")
reconnect_key = H.create_preauth_key(server, alice_id)
H.reset_client(client2)
H.connect_client(client2, reconnect_key, "del-reconnect")
new_node = H.get_node_by_name(server, "del-reconnect")
if new_node["id"] == old_id, do: raise("new node should have different ID")
IO.puts("key usage ok")

# ==========================================================================
# PHASE 7: Groups
# ==========================================================================
IO.puts("--- groups ---")

eve_id = H.create_user_and_get_id(server, "eve@example.com")
alice_key = H.create_preauth_key(server, alice_id)
eve_key = H.create_preauth_key(server, eve_id)

H.reset_client(client1)
H.reset_client(client2)
H.connect_client(client1, alice_key, "alice-node")
H.connect_client(client2, eve_key, "eve-node")

alice_ip = H.get_client_ip(client1)
eve_ip = H.get_client_ip(client2)
unless alice_ip && eve_ip, do: raise("group clients not connected")

alice_node = H.get_node_by_name(server, "alice-node")
H.railscale(server, "nodes tags set #{alice_node["id"]} server")

Attest.succeed(client2, "timeout 10 ping -c 2 #{alice_ip}")
Attest.succeed(client1, "timeout 10 ping -c 2 #{eve_ip}")
IO.puts("groups ok")

# ==========================================================================
# PHASE 8: REST API
# ==========================================================================
IO.puts("--- rest api ---")

H.railscale(server, "users create admin@example.com --display-name 'API Admin'")
users = H.railscale_json(server, "users list")
admin = Enum.find(users, fn u -> u["email"] == "admin@example.com" end)
admin_id = admin["id"]
api_key = H.create_api_key_for_user(server, admin_id)

# auth check
status = H.api_status(server, "/api/v1/user")
unless status == 401, do: raise("expected 401, got #{status}")

# CRUD users
result = H.api_get(server, "/api/v1/user", api_key)
unless Map.has_key?(result, "users"), do: raise("missing users key")

result = H.api_post(server, "/api/v1/user", api_key, %{"name" => "restuser"})
rest_user_id = result["user"]["id"]
result = H.api_post(server, "/api/v1/user/#{rest_user_id}/rename/renameduser", api_key)
unless result["user"]["name"] == "renameduser", do: raise("rename failed")
H.api_delete(server, "/api/v1/user/#{rest_user_id}", api_key)

# nodes
result = H.api_get(server, "/api/v1/node", api_key)
unless Map.has_key?(result, "nodes"), do: raise("missing nodes key")

# preauth keys
result = H.api_get(server, "/api/v1/preauthkey", api_key)
unless Map.has_key?(result, "preAuthKeys"), do: raise("missing preAuthKeys")

result = H.api_post(server, "/api/v1/preauthkey", api_key,
  %{"user" => if(is_binary(admin_id), do: String.to_integer(admin_id), else: admin_id),
    "reusable" => false, "ephemeral" => false, "aclTags" => []})
new_pak_id = result["preAuthKey"]["id"]
pak_id_int = if is_binary(new_pak_id), do: String.to_integer(new_pak_id), else: new_pak_id
H.api_post(server, "/api/v1/preauthkey/expire", api_key, %{"id" => pak_id_int})

# api keys
result = H.api_get(server, "/api/v1/apikey", api_key)
unless Map.has_key?(result, "apiKeys"), do: raise("missing apiKeys")

admin_id_int = if is_binary(admin_id), do: String.to_integer(admin_id), else: admin_id
result = H.api_post(server, "/api/v1/apikey", api_key, %{"user" => admin_id_int})
new_api_key_prefix = result["key"]["prefix"]
H.api_delete(server, "/api/v1/apikey/#{new_api_key_prefix}", api_key)

# policy
result = H.api_get(server, "/api/v1/policy", api_key)
unless Map.has_key?(result, "policy"), do: raise("missing policy")
original_policy = result["policy"]

new_policy = Jason.encode!(%{"groups" => %{"group:test" => ["test@example.com"]}, "grants" => [%{"src" => ["*"], "dst" => ["*"], "ip" => ["*"]}]})
H.api_put(server, "/api/v1/policy", api_key, %{"policy" => new_policy})
H.api_put(server, "/api/v1/policy", api_key, %{"policy" => original_policy})

# rate limiting
got_limited = Enum.reduce_while(1..100, false, fn i, _acc ->
  status = H.api_status(server, "/api/v1/user", "GET", api_key)
  if status == 429, do: {:halt, true}, else: {:cont, false}
end)
unless got_limited, do: raise("rate limit not hit")

IO.puts("rest api ok")

# ==========================================================================
# PHASE 9: SSH Policy
# ==========================================================================
IO.puts("--- ssh policy ---")

H.railscale(server, "users create sshuser1@example.com")
H.railscale(server, "users create sshuser2@example.com")
users = H.railscale_json(server, "users list")
sshuser1_id = Enum.find(users, fn u -> u["email"] == "sshuser1@example.com" end) |> Map.fetch!("id")
sshuser2_id = Enum.find(users, fn u -> u["email"] == "sshuser2@example.com" end) |> Map.fetch!("id")

key1a = H.create_preauth_key(server, sshuser1_id)
key1b = H.create_preauth_key(server, sshuser1_id)
key2 = H.create_preauth_key(server, sshuser2_id)

H.reset_client(client1)
H.reset_client(client2)
H.connect_client(client1, key1a, "ssh-u1-c1", ssh: true)
H.connect_client(client2, key1b, "ssh-u1-c2", ssh: true)

u1c2_ip = H.get_client_ip(client2)
unless u1c2_ip, do: raise("ssh client2 no IP")

# same user, non-root -> should work
{ok, _} = H.try_ssh(client1, u1c2_ip, "testuser")
unless ok, do: raise("same-user ssh should succeed")
IO.puts("same-user ssh ok")

# same user, root -> blocked
{ok, _} = H.try_ssh(client1, u1c2_ip, "root")
if ok, do: raise("root ssh should be blocked")
IO.puts("root ssh blocked")

# different user -> blocked
H.reset_client(client2)
H.connect_client(client2, key2, "ssh-u2", ssh: true)
u2_ip = H.get_client_ip(client2)
unless u2_ip, do: raise("ssh user2 no IP")
{ok, _} = H.try_ssh(client1, u2_ip, "testuser")
if ok, do: raise("cross-user ssh should be blocked")
IO.puts("cross-user ssh blocked")

IO.puts("ssh policy ok")

# ==========================================================================
# PHASE 10: Tailnet Lock
# ==========================================================================
IO.puts("--- tailnet lock ---")

output = H.railscale(server, "lock status")
unless String.contains?(String.downcase(output), "disabled"), do: raise("lock should be disabled")

output = H.railscale(server, "lock init --force --disablement-secrets 2")
unless String.contains?(String.downcase(output), "initialised") or
       String.contains?(String.downcase(output), "success"),
  do: raise("lock init failed: #{output}")

# extract private key
private_key =
  output
  |> String.split("\n")
  |> Enum.find_value(fn line ->
    if String.contains?(line, "nlpriv:") do
      line |> String.split() |> Enum.find(& String.starts_with?(&1, "nlpriv:"))
    end
  end) || raise("no private key in lock init output")

# extract disablement secrets
secrets =
  output
  |> String.split("\n")
  |> Enum.filter(fn line -> Regex.match?(~r/^\s*\d+:/, line) end)
  |> Enum.map(fn line ->
    line |> String.split(":") |> List.last() |> String.trim()
  end)
  |> Enum.filter(fn s -> String.length(s) == 64 end)

unless length(secrets) == 2, do: raise("expected 2 disablement secrets, got #{length(secrets)}")

output = H.railscale(server, "lock status")
unless String.contains?(String.downcase(output), "enabled"), do: raise("lock should be enabled")

# sign a node
nodes_list = H.railscale_json(server, "nodes list")
unless length(nodes_list) > 0, do: raise("no nodes to sign")
sign_node_id = hd(nodes_list)["id"]
output = H.railscale(server, "lock sign #{sign_node_id} --key #{private_key}")
unless String.contains?(String.downcase(output), "success") or
       String.contains?(String.downcase(output), "signed"),
  do: raise("lock sign failed: #{output}")

# disable
output = H.railscale(server, "lock disable #{hd(secrets)}")
unless String.contains?(String.downcase(output), "disabled"), do: raise("lock disable failed")

output = H.railscale(server, "lock status")
unless String.contains?(String.downcase(output), "disabled"), do: raise("lock should be disabled again")

IO.puts("tailnet lock ok")

# ==========================================================================
IO.puts("\n" <> String.duplicate("=", 70))
IO.puts("ALL TESTS PASSED!")
IO.puts(String.duplicate("=", 70))
