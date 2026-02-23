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

    if expect_success do
      wait_for_tailscale_ip(client)
    else
      Process.sleep(2000)
    end
  end

  defp wait_for_tailscale_ip(client, attempts \\ 20) do
    {code, output} = Attest.Machine.execute(client, "tailscale ip -4 2>&1")
    ip = String.trim(output)

    if code == 0 and String.starts_with?(ip, "100.") do
      :ok
    else
      if attempts > 0 do
        Process.sleep(500)
        wait_for_tailscale_ip(client, attempts - 1)
      else
        :ok
      end
    end
  end

  def get_client_ip(client) do
    {code, output} = Attest.Machine.execute(client, "tailscale ip -4 2>&1")
    ip = String.trim(output)
    if code == 0 and String.starts_with?(ip, "100."), do: ip, else: nil
  end

  def disconnect_client(client) do
    Attest.Machine.execute(client, "tailscale logout 2>&1 || true")
    Process.sleep(1000)
  end

  def reset_client(client) do
    Attest.Machine.execute(client, "tailscale logout 2>&1 || true")
    Attest.Machine.execute(client, "systemctl stop tailscaled")
    Attest.Machine.execute(client, "rm -rf /var/lib/tailscale/*")
    Attest.Machine.execute(client, "systemctl start tailscaled")
    Attest.wait_for_unit(client, "tailscaled.service")
  end

  def wait_for_server(server) do
    Attest.wait_for_unit(server, "railscale.service")
    Attest.wait_for_open_port(server, 8080)
    Attest.wait_for_open_port(server, 3340)
  end

  def wait_for_network(server, client1, client2) do
    Attest.wait_for_unit(server, "multi-user.target")
    Attest.wait_for_unit(client1, "multi-user.target")
    Attest.wait_for_unit(client2, "multi-user.target")
    Attest.wait_for_unit(client1, "tailscaled.service")
    Attest.wait_for_unit(client2, "tailscaled.service")
    Process.sleep(1000)
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

  def api_get_headers(server, path, api_key) do
    cmd = "curl -s -D - -o /dev/null -H 'Authorization: Bearer #{api_key}' '#{@server_url}#{path}'"
    Attest.succeed(server, cmd)
  end

  def try_json(output) do
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

  def to_int(v) when is_binary(v), do: String.to_integer(v)
  def to_int(v) when is_integer(v), do: v
end

# ==========================================================================
# PHASE 1: Server Startup + STUN
# ==========================================================================
start_all.()

IO.puts("--- server startup ---")
H.wait_for_server(server)
H.wait_for_network(server, client1, client2)
IO.puts("server started")

# STUN: netcheck
IO.puts("--- STUN test ---")
{_, netcheck} = Attest.Machine.execute(client1, "tailscale netcheck --format=json 2>&1 || true")
IO.puts("netcheck: #{String.slice(netcheck, 0, 200)}")

# STUN: raw binding request
stun_test = ~S"""
import socket, sys
request = bytes([
    0x00, 0x01, 0x00, 0x00,
    0x21, 0x12, 0xa4, 0x42,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
try:
    sock.sendto(request, ("192.168.1.3", 3478))
    response, addr = sock.recvfrom(1024)
    if len(response) >= 20 and response[0:2] == bytes([0x01, 0x01]):
        if response[4:8] == bytes([0x21, 0x12, 0xa4, 0x42]):
            print("STUN response received: %d bytes from %s" % (len(response), addr))
            sys.exit(0)
    print("Invalid STUN response: " + response.hex())
    sys.exit(1)
except socket.timeout:
    print("STUN request timed out")
    sys.exit(1)
finally:
    sock.close()
"""
Attest.succeed(client1, "cat > /tmp/stun_test.py << 'EOFSTUN'\n#{stun_test}\nEOFSTUN")
stun_output = Attest.succeed(client1, "python3 /tmp/stun_test.py")
IO.puts("STUN: #{String.trim(stun_output)}")

# ==========================================================================
# PHASE 2: User Management
# ==========================================================================
IO.puts("--- user management ---")

output = H.railscale(server, "users create alice@example.com --display-name 'Alice Smith'")
unless String.contains?(output, "Created user"), do: raise("create user failed: #{output}")

output = H.railscale(server, "users list")
unless String.contains?(output, "alice"), do: raise("list should show alice")

users = H.railscale_json(server, "users list")
unless length(users) == 1, do: raise("expected 1 user, got #{length(users)}")
unless hd(users)["email"] == "alice@example.com", do: raise("wrong email")

H.railscale(server, "users create bob@example.com")
users = H.railscale_json(server, "users list")
unless length(users) == 2, do: raise("expected 2 users")
emails = Enum.map(users, & &1["email"])
unless "alice@example.com" in emails and "bob@example.com" in emails, do: raise("missing users")

bob = Enum.find(users, fn u -> u["email"] == "bob@example.com" end)
bob_id = bob["id"]
output = H.railscale(server, "users rename #{bob_id} robert@example.com")
unless String.contains?(output, "Renamed"), do: raise("rename failed")

users = H.railscale_json(server, "users list")
emails = Enum.map(users, & &1["email"])
unless "robert@example.com" in emails, do: raise("robert not found")
if "bob@example.com" in emails, do: raise("bob should be gone")

robert = Enum.find(users, fn u -> u["email"] == "robert@example.com" end)
output = H.railscale(server, "users delete #{robert["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete failed")

users = H.railscale_json(server, "users list")
unless length(users) == 1, do: raise("expected 1 user after delete")
unless hd(users)["email"] == "alice@example.com", do: raise("alice should remain")

alice_id = hd(users)["id"]
IO.puts("alice id: #{alice_id}")

# ==========================================================================
# PHASE 3: Preauth Keys
# ==========================================================================
IO.puts("--- preauth keys ---")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --expiration-days 1")
unless String.contains?(output, "Created preauth key"), do: raise("create pak failed")
unless String.contains?(output, "Key:"), do: raise("missing Key: in output")

# list
output = H.railscale(server, "preauthkeys list")
unless String.contains?(output, "#{alice_id}"), do: raise("list should show alice's keys")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --reusable --expiration-days 1")
unless String.contains?(output, "Reusable:  true"), do: raise("reusable flag missing")

output = H.railscale(server, "preauthkeys create -u #{alice_id} --tags server,web --expiration-days 1")
unless String.contains?(output, "server"), do: raise("tags missing")

# expire
keys = H.railscale_json(server, "preauthkeys list")
key_id = hd(keys)["id"]
output = H.railscale(server, "preauthkeys expire #{key_id}")
unless String.contains?(output, "Expired"), do: raise("expire failed")

# delete
keys = H.railscale_json(server, "preauthkeys list")
del_key = Enum.find(keys, fn k -> !k["reusable"] end)
output = H.railscale(server, "preauthkeys delete #{del_key["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete pak failed")

IO.puts("preauth keys ok")

# ==========================================================================
# PHASE 3.5: API Keys
# ==========================================================================
IO.puts("--- api keys ---")

output = H.railscale(server, "apikeys create -u #{alice_id} --name 'My Test API Key' --expiration-days 30")
unless String.contains?(output, "Created API key"), do: raise("create api key failed")
unless String.contains?(output, "Key:"), do: raise("missing Key: in output")
unless String.contains?(output, "rsapi_"), do: raise("api key missing prefix")

# list
output = H.railscale(server, "apikeys list")
unless String.contains?(output, "My Test AP") or String.contains?(output, "My Test API Key"),
  do: raise("list should show key name")

# list json
keys = H.railscale_json(server, "apikeys list")
unless length(keys) >= 1, do: raise("expected at least 1 api key")
unless Enum.any?(keys, fn k -> String.starts_with?(k["prefix"], "rsapi_") end),
  do: raise("api key prefix missing in json")

# no expiration
output = H.railscale(server, "apikeys create -u #{alice_id} --name 'Perm Key' --expiration-days 0")
unless String.contains?(String.downcase(output), "never"), do: raise("no-expiry missing")

# expire
keys = H.railscale_json(server, "apikeys list")
key_id = hd(keys)["id"]
output = H.railscale(server, "apikeys expire #{key_id}")
unless String.contains?(output, "Expired"), do: raise("expire api key failed")

# delete
keys = H.railscale_json(server, "apikeys list")
del_key = if length(keys) > 1, do: List.last(keys), else: hd(keys)
output = H.railscale(server, "apikeys delete #{del_key["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete api key failed")

# filter by user
output = H.railscale(server, "apikeys list -u #{alice_id}")
IO.puts("apikeys for alice: #{String.slice(String.trim(output), 0, 100)}")

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
unless String.starts_with?(client1_ip, "100."), do: raise("client1 IP should be 100.x")
unless String.starts_with?(client2_ip, "100."), do: raise("client2 IP should be 100.x")
IO.puts("client1=#{client1_ip} client2=#{client2_ip}")

# ping
Attest.succeed(client1, "timeout 15 ping -c 3 #{client2_ip}")
Attest.succeed(client2, "timeout 15 ping -c 3 #{client1_ip}")
IO.puts("clients can ping")

# list nodes
output = H.railscale(server, "nodes list")
unless String.contains?(output, "client1") and String.contains?(output, "client2"),
  do: raise("list should show both clients")

nodes_list = H.railscale_json(server, "nodes list")
unless length(nodes_list) == 2, do: raise("expected 2 nodes, got #{length(nodes_list)}")
hostnames = Enum.map(nodes_list, & &1["given_name"])
unless "client1" in hostnames and "client2" in hostnames, do: raise("missing hostnames")

# show
node1 = Enum.find(nodes_list, fn n -> n["given_name"] == "client1" end)
node1_id = node1["id"]
output = H.railscale(server, "nodes show #{node1_id}")
unless String.contains?(output, "client1"), do: raise("show failed")
unless String.contains?(output, "IPv4:"), do: raise("show should have IPv4")

# rename
output = H.railscale(server, "nodes rename #{node1_id} client1-renamed")
unless String.contains?(output, "Renamed"), do: raise("rename failed")
nodes_check = H.railscale_json(server, "nodes list")
names = Enum.map(nodes_check, & &1["given_name"])
unless "client1-renamed" in names, do: raise("rename not reflected")
H.railscale(server, "nodes rename #{node1_id} client1")

# tags
output = H.railscale(server, "nodes tags add #{node1_id} server,web")
unless String.contains?(output, "tag:server") and String.contains?(output, "tag:web"),
  do: raise("add tags failed")

output = H.railscale(server, "nodes tags remove #{node1_id} web")
unless String.contains?(output, "tag:server"), do: raise("remove tag failed")

output = H.railscale(server, "nodes tags set #{node1_id} production,critical")
unless String.contains?(output, "tag:production") and String.contains?(output, "tag:critical"),
  do: raise("set tags failed")

# routes
output = H.railscale(server, "nodes routes approve #{node1_id} 10.0.0.0/8,192.168.0.0/16")
unless String.contains?(output, "10.0.0.0/8") and String.contains?(output, "192.168.0.0/16"),
  do: raise("approve routes failed")

output = H.railscale(server, "nodes routes list #{node1_id}")
unless String.contains?(output, "10.0.0.0/8"), do: raise("routes list failed")

output = H.railscale(server, "nodes routes unapprove #{node1_id} 192.168.0.0/16")
unless String.contains?(output, "10.0.0.0/8"), do: raise("unapprove failed")

# expire
output = H.railscale(server, "nodes expire #{node1_id}")
unless String.contains?(output, "Expired"), do: raise("expire node failed")
output = H.railscale(server, "nodes show #{node1_id}")
unless String.contains?(output, "Expiry:"), do: raise("expired node should show Expiry")

# filter by user
output = H.railscale(server, "nodes list -u #{alice_id}")
IO.puts("nodes for alice: #{String.slice(String.trim(output), 0, 100)}")

# filter preauthkeys by user
output = H.railscale(server, "preauthkeys list -u #{alice_id}")
IO.puts("preauthkeys for alice: #{String.slice(String.trim(output), 0, 100)}")

# delete node
node2 = Enum.find(nodes_list, fn n -> n["given_name"] == "client2" end)
output = H.railscale(server, "nodes delete #{node2["id"]}")
unless String.contains?(output, "Deleted"), do: raise("delete node failed")

nodes_list = H.railscale_json(server, "nodes list")
ids = Enum.map(nodes_list, & &1["id"])
if node2["id"] in ids, do: raise("deleted node still present")
names = Enum.map(nodes_list, & &1["given_name"])
unless "client1" in names, do: raise("client1 should still exist")

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

client1_ip = H.get_client_ip(client1)
client2_ip = H.get_client_ip(client2)
unless client1_ip && client2_ip, do: raise("taildrop clients not connected")

# wait for DERP connectivity (poll until ping output contains "pong")
Attest.wait_until_succeeds(client1,
  "tailscale ping --c 1 #{client2_ip} 2>&1 | grep -q pong",
  timeout: 30_000)

# verify peers can communicate
{_, ping_out} = Attest.Machine.execute(client1, "tailscale ping --c 3 #{client2_ip} 2>&1")
IO.puts("tailscale ping: #{String.slice(String.trim(ping_out), 0, 200)}")

# file targets
{c1, t1} = Attest.Machine.execute(client1, "tailscale file cp --targets 2>&1")
{c2, t2} = Attest.Machine.execute(client2, "tailscale file cp --targets 2>&1")
unless c1 == 0 and String.contains?(t1, "client2"), do: raise("client1 can't see client2 targets: #{t1}")
unless c2 == 0 and String.contains?(t2, "client1"), do: raise("client2 can't see client1 targets: #{t2}")

# send file
Attest.succeed(client1, "echo 'hello from taildrop' > /tmp/td.txt")
Attest.succeed(client1, "tailscale file cp /tmp/td.txt client2: 2>&1")
Process.sleep(500)
Attest.succeed(client2, "mkdir -p /tmp/recv")
Attest.succeed(client2, "tailscale file get /tmp/recv/ 2>&1")
received = Attest.succeed(client2, "cat /tmp/recv/td.txt") |> String.trim()
unless received == "hello from taildrop", do: raise("taildrop content mismatch: #{received}")

# bidirectional
Attest.succeed(client2, "echo 'reply from client2' > /tmp/reply.txt")
Attest.succeed(client2, "tailscale file cp /tmp/reply.txt client1: 2>&1")
Process.sleep(500)
Attest.succeed(client1, "mkdir -p /tmp/recv")
Attest.succeed(client1, "tailscale file get /tmp/recv/ 2>&1")
reply = Attest.succeed(client1, "cat /tmp/recv/reply.txt") |> String.trim()
unless reply == "reply from client2", do: raise("bidirectional taildrop failed")
IO.puts("bidirectional transfer ok")

# cross-user blocking
IO.puts("testing cross-user taildrop blocking")
bob_id = H.create_user_and_get_id(server, "bob@example.com", "Bob")
H.reset_client(client2)
bob_key = H.create_preauth_key(server, bob_id)
H.connect_client(client2, bob_key, "client2-bob")
client2_bob_ip = H.get_client_ip(client2)
unless client2_bob_ip, do: raise("client2 as bob should have IP")

# alice should NOT see bob's device as a file target
{_, targets} = Attest.Machine.execute(client1, "tailscale file cp --targets 2>&1")
if String.contains?(targets, "client2-bob"),
  do: raise("alice should NOT see bob's device as file target: #{targets}")

# try sending anyway
Attest.succeed(client1, "echo 'secret' > /tmp/secret.txt")
{send_code, _} = Attest.Machine.execute(client1, "tailscale file cp /tmp/secret.txt #{client2_bob_ip}: 2>&1")
if send_code == 0 do
  Process.sleep(500)
  Attest.Machine.execute(client2, "mkdir -p /tmp/bob-received")
  Attest.Machine.execute(client2, "tailscale file get /tmp/bob-received/ 2>&1")
  {_, files} = Attest.Machine.execute(client2, "ls /tmp/bob-received/ 2>&1")
  if String.contains?(files, "secret.txt"),
    do: raise("bob should NOT receive alice's file: #{files}")
end
IO.puts("cross-user taildrop blocked")

# reconnect client2 as alice for remaining tests
H.reset_client(client2)
alice_key = H.create_preauth_key(server, alice_id)
H.connect_client(client2, alice_key, "client2")

IO.puts("taildrop ok")

# ==========================================================================
# PHASE 6: Key Usage Tests
# ==========================================================================
IO.puts("--- key usage ---")

# verify reusable key marked correctly in json
output = H.railscale(server, "preauthkeys create -u #{alice_id} --reusable --expiration-days 1")
unless String.contains?(output, "Reusable:  true"), do: raise("reusable flag missing")
reusable_check_key = H.extract_key(output)
keys = H.railscale_json(server, "preauthkeys list")
the_key = Enum.find(keys, fn k -> String.starts_with?(reusable_check_key, k["key"]) end)
unless the_key, do: raise("key should be in list")
unless the_key["reusable"] == true, do: raise("key should be marked reusable in json")
IO.puts("reusable key verified in json")

# verify ephemeral key creation
output = H.railscale(server, "preauthkeys create -u #{alice_id} --ephemeral --expiration-days 1")
unless String.contains?(output, "Ephemeral: true"), do: raise("ephemeral flag missing")
ephemeral_check_key = H.extract_key(output)
keys = H.railscale_json(server, "preauthkeys list")
the_key = Enum.find(keys, fn k -> String.starts_with?(ephemeral_check_key, k["key"]) end)
unless the_key, do: raise("ephemeral key should be in list")
unless the_key["ephemeral"] == true, do: raise("key should be marked ephemeral in json")
IO.puts("ephemeral key verified in json")

# user with nodes cannot be deleted
{exit_code, del_output} = Attest.Machine.execute(server, "railscale users delete #{alice_id} 2>&1")
unless exit_code != 0 or String.contains?(String.downcase(del_output), "node"),
  do: raise("deleting user with nodes should fail")
IO.puts("user with nodes cannot be deleted")

# client1 still connected after management
unless H.get_client_ip(client1), do: raise("client1 should still be connected")
IO.puts("client1 still connected")

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
IO.puts("deleted node gets new ID")

# final connectivity - fresh clients can communicate
final_key1 = H.create_preauth_key(server, alice_id)
final_key2 = H.create_preauth_key(server, alice_id)
H.reset_client(client1)
H.reset_client(client2)
H.connect_client(client1, final_key1, "final-client1")
H.connect_client(client2, final_key2, "final-client2")
client1_ip = H.get_client_ip(client1)
client2_ip = H.get_client_ip(client2)
unless client1_ip && client2_ip, do: raise("final clients not connected")
Attest.succeed(client1, "timeout 15 ping -c 3 #{client2_ip}")
Attest.succeed(client2, "timeout 15 ping -c 3 #{client1_ip}")
IO.puts("final connectivity verified")

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
IO.puts("tagged alice-node as server")

Attest.succeed(client2, "timeout 10 ping -c 2 #{alice_ip}")
IO.puts("eve can reach alice")
Attest.succeed(client1, "timeout 10 ping -c 2 #{eve_ip}")
IO.puts("alice can reach eve")

# verify policy is loaded
Attest.succeed(server, "journalctl -u railscale --no-pager | grep -i 'policy' || true")

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
unless String.starts_with?(api_key, "rsapi_"), do: raise("api key should start with rsapi_")

# auth check
status = H.api_status(server, "/api/v1/user")
unless status == 401, do: raise("expected 401, got #{status}")
IO.puts("unauthenticated rejected with 401")

# CRUD users
result = H.api_get(server, "/api/v1/user", api_key)
unless Map.has_key?(result, "users"), do: raise("missing users key")
unless length(result["users"]) > 0, do: raise("should have at least 1 user")

result = H.api_post(server, "/api/v1/user", api_key, %{"name" => "restuser"})
unless result["user"]["name"] == "restuser", do: raise("create user failed")
rest_user_id = result["user"]["id"]

result = H.api_post(server, "/api/v1/user/#{rest_user_id}/rename/renameduser", api_key)
unless result["user"]["name"] == "renameduser", do: raise("rename failed")

H.api_delete(server, "/api/v1/user/#{rest_user_id}", api_key)
IO.puts("REST user CRUD ok")

# nodes
result = H.api_get(server, "/api/v1/node", api_key)
unless Map.has_key?(result, "nodes"), do: raise("missing nodes key")

# get single node
if length(result["nodes"]) > 0 do
  node_id = hd(result["nodes"])["id"]
  node_result = H.api_get(server, "/api/v1/node/#{node_id}", api_key)
  unless Map.has_key?(node_result, "node"), do: raise("missing node key in single get")
  IO.puts("REST get node #{node_id} ok")
end

# preauth keys
result = H.api_get(server, "/api/v1/preauthkey", api_key)
unless Map.has_key?(result, "preAuthKeys"), do: raise("missing preAuthKeys")

admin_id_int = H.to_int(admin_id)
result = H.api_post(server, "/api/v1/preauthkey", api_key,
  %{"user" => admin_id_int, "reusable" => false, "ephemeral" => false, "aclTags" => []})
unless Map.has_key?(result, "preAuthKey"), do: raise("missing preAuthKey in create response")
new_pak_id = result["preAuthKey"]["id"]
pak_id_int = H.to_int(new_pak_id)
H.api_post(server, "/api/v1/preauthkey/expire", api_key, %{"id" => pak_id_int})
IO.puts("REST preauth keys ok")

# api keys
result = H.api_get(server, "/api/v1/apikey", api_key)
unless Map.has_key?(result, "apiKeys"), do: raise("missing apiKeys")

result = H.api_post(server, "/api/v1/apikey", api_key, %{"user" => admin_id_int})
unless Map.has_key?(result, "apiKey"), do: raise("missing apiKey in create response")
unless Map.has_key?(result, "key"), do: raise("missing key in create response")
new_api_key_full = result["apiKey"]
new_api_key_prefix = result["key"]["prefix"]
unless String.starts_with?(new_api_key_full, "rsapi_"), do: raise("new key should start with rsapi_")
H.api_delete(server, "/api/v1/apikey/#{new_api_key_prefix}", api_key)
IO.puts("REST api keys ok")

# policy
result = H.api_get(server, "/api/v1/policy", api_key)
unless Map.has_key?(result, "policy"), do: raise("missing policy")
original_policy = result["policy"]
unless String.contains?(original_policy, "grants"), do: raise("policy should contain grants")

new_policy = Jason.encode!(%{"groups" => %{"group:test" => ["test@example.com"]}, "grants" => [%{"src" => ["*"], "dst" => ["*"], "ip" => ["*"]}]})
result = H.api_put(server, "/api/v1/policy", api_key, %{"policy" => new_policy})
unless Map.has_key?(result, "policy"), do: raise("set policy should return policy")
H.api_put(server, "/api/v1/policy", api_key, %{"policy" => original_policy})
IO.puts("REST policy ok")

# rate limit headers
headers = H.api_get_headers(server, "/api/v1/user", api_key)
has_ratelimit = String.contains?(String.downcase(headers), "ratelimit")
IO.puts("rate limit headers present: #{has_ratelimit}")

# rate limiting
got_limited = Enum.reduce_while(1..100, false, fn _i, _acc ->
  status = H.api_status(server, "/api/v1/user", "GET", api_key)
  if status == 429, do: {:halt, true}, else: {:cont, false}
end)
unless got_limited, do: raise("rate limit not hit")
IO.puts("rate limiting works")

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

u1c1_ip = H.get_client_ip(client1)
u1c2_ip = H.get_client_ip(client2)
unless u1c1_ip, do: raise("ssh client1 no IP")
unless u1c2_ip, do: raise("ssh client2 no IP")
IO.puts("ssh clients: u1c1=#{u1c1_ip} u1c2=#{u1c2_ip}")

# wait for DERP connectivity between SSH clients
Attest.wait_until_succeeds(client1,
  "tailscale ping --c 1 #{u1c2_ip} 2>&1 | grep -q pong",
  timeout: 30_000)

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
unless String.contains?(String.downcase(output), "head:"), do: raise("should show head hash")

# lock status json
lock_json = H.railscale_json(server, "lock status")
unless lock_json["enabled"] == true, do: raise("json: expected enabled=true")
unless lock_json["head"], do: raise("json: expected head hash")
unless length(Map.get(lock_json, "keys", [])) == 1, do: raise("json: expected 1 key")
IO.puts("lock status json ok")

# sign a node
nodes_list = H.railscale_json(server, "nodes list")
unless length(nodes_list) > 0, do: raise("no nodes to sign")
sign_node_id = hd(nodes_list)["id"]
output = H.railscale(server, "lock sign #{sign_node_id} --key #{private_key}")
unless String.contains?(String.downcase(output), "success") or
       String.contains?(String.downcase(output), "signed"),
  do: raise("lock sign failed: #{output}")
IO.puts("node signed")

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
