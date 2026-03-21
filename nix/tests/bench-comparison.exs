# Headscale vs Railscale benchmark comparison
#
# 4 VMs: rs_server, hs_server, rs_client, hs_client
# Measures server-side operation latency for both control servers.

defmodule Bench do
  def wait_for_tailscale_ip(client, attempts \\ 30) do
    {code, output} = Attest.Machine.execute(client, "tailscale ip -4 2>&1")
    ip = String.trim(output)

    if code == 0 and String.starts_with?(ip, "100.") do
      ip
    else
      if attempts > 0 do
        Process.sleep(500)
        wait_for_tailscale_ip(client, attempts - 1)
      else
        nil
      end
    end
  end

  def connect_client(client, server_url, key, hostname) do
    Attest.Machine.execute(client,
      "timeout 30 tailscale up --login-server=#{server_url}" <>
      " --authkey=#{key} --hostname=#{hostname} 2>&1 || true"
    )
    wait_for_tailscale_ip(client)
  end

  @doc "measure a command executed on a server, returns {elapsed_us, output}"
  def timed_exec(server, cmd) do
    start = System.monotonic_time(:microsecond)
    {_, output} = Attest.Machine.execute(server, cmd)
    elapsed = System.monotonic_time(:microsecond) - start
    {elapsed, output}
  end

  @doc "measure N iterations of a command on a server"
  def bench_cmd(server, cmd, n) do
    Enum.map(1..n, fn _ ->
      {elapsed, _} = timed_exec(server, cmd)
      elapsed
    end)
  end

  def format_us(us) when us >= 1_000_000, do: "#{Float.round(us / 1_000_000, 2)}s"
  def format_us(us) when us >= 1_000, do: "#{Float.round(us / 1_000, 2)}ms"
  def format_us(us), do: "#{us}us"

  def print_result(label, timings_us) do
    sorted = Enum.sort(timings_us)
    count = length(sorted)
    total = Enum.sum(sorted)
    mean = div(total, max(count, 1))
    p50 = Enum.at(sorted, div(count * 50, 100))
    p95 = Enum.at(sorted, div(count * 95, 100) |> min(count - 1))
    max_v = List.last(sorted) || 0

    IO.puts("")
    IO.puts("── #{label} (#{count} samples) ──")
    IO.puts("  total:  #{format_us(total)}")
    IO.puts("  mean:   #{format_us(mean)}")
    IO.puts("  p50:    #{format_us(p50)}")
    IO.puts("  p95:    #{format_us(p95)}")
    IO.puts("  max:    #{format_us(max_v)}")
  end
end

# ── start VMs ──

start_all.()

IO.puts("\n=== waiting for control servers ===\n")

Attest.wait_for_unit(rs_server, "railscale.service")
Attest.wait_for_open_port(rs_server, 8080)
IO.puts("railscale: ready")

Attest.wait_for_unit(hs_server, "headscale.service")
Attest.wait_for_open_port(hs_server, 8080)
IO.puts("headscale: ready")

Attest.wait_for_unit(rs_client, "tailscaled.service")
Attest.wait_for_unit(hs_client, "tailscaled.service")
IO.puts("clients: ready")

# ── setup: create users and keys ──

IO.puts("\n=== setup ===\n")

Attest.succeed(rs_server, "railscale users create bench@test.com")
rs_key_output = Attest.succeed(rs_server, "railscale preauthkeys create --user 1 --reusable")
rs_key = rs_key_output
  |> String.split("\n")
  |> Enum.find_value(fn line ->
    if String.contains?(line, "Key:") do
      line |> String.split("Key:") |> List.last() |> String.trim()
    end
  end)
IO.puts("railscale key: #{String.slice(rs_key || "", 0..15)}...")

Attest.succeed(hs_server, "headscale users create bench")
{_, hs_user_json} = Attest.Machine.execute(hs_server, "headscale users list --output json 2>&1")
hs_user_id = case Jason.decode(String.trim(hs_user_json)) do
  {:ok, [%{"id" => id} | _]} -> id
  _ -> 1
end
{_, hs_key_output} = Attest.Machine.execute(hs_server,
  "headscale preauthkeys create --user #{hs_user_id} --reusable --output json 2>&1"
)
hs_key = case Jason.decode(String.trim(hs_key_output)) do
  {:ok, %{"key" => key}} -> key
  _ -> String.trim(hs_key_output)
end
IO.puts("headscale key: #{String.slice(hs_key, 0..15)}...")

# register one node per server so we have data to query
Bench.connect_client(rs_client, "http://rs-server:8080", rs_key, "rs-bench-node")
IO.puts("railscale client registered")
Bench.connect_client(hs_client, "http://hs-server:8080", hs_key, "hs-bench-node")
IO.puts("headscale client registered")

Process.sleep(2000)

# ── benchmark: server-side admin CLI ops (unix socket / gRPC) ──

n = 20

IO.puts("\n=== benchmark: admin CLI operations (#{n} iterations) ===\n")

# -- user list --
rs_user_list = Bench.bench_cmd(rs_server, "railscale users list -o json 2>&1", n)
hs_user_list = Bench.bench_cmd(hs_server, "headscale users list --output json 2>&1", n)
Bench.print_result("railscale: users list", rs_user_list)
Bench.print_result("headscale: users list", hs_user_list)

# -- node list --
rs_node_list = Bench.bench_cmd(rs_server, "railscale nodes list -o json 2>&1", n)
hs_node_list = Bench.bench_cmd(hs_server, "headscale nodes list --output json 2>&1", n)
Bench.print_result("railscale: nodes list", rs_node_list)
Bench.print_result("headscale: nodes list", hs_node_list)

# -- preauth key create --
rs_key_create = Bench.bench_cmd(rs_server, "railscale preauthkeys create --user 1 2>&1", n)
hs_key_create = Bench.bench_cmd(hs_server,
  "headscale preauthkeys create --user #{hs_user_id} --output json 2>&1", n)
Bench.print_result("railscale: key create", rs_key_create)
Bench.print_result("headscale: key create", hs_key_create)

# -- preauth key list --
rs_key_list = Bench.bench_cmd(rs_server, "railscale preauthkeys list --user 1 -o json 2>&1", n)
hs_key_list = Bench.bench_cmd(hs_server,
  "headscale preauthkeys list --user #{hs_user_id} --output json 2>&1", n)
Bench.print_result("railscale: key list", rs_key_list)
Bench.print_result("headscale: key list", hs_key_list)

# ── benchmark: map poll latency (client-side, includes network) ──

IO.puts("\n=== benchmark: map poll latency (10 rounds) ===\n")

rs_poll = Enum.map(1..10, fn _ ->
  start = System.monotonic_time(:microsecond)
  Attest.Machine.execute(rs_client, "tailscale debug netmap >/dev/null 2>&1")
  System.monotonic_time(:microsecond) - start
end)

hs_poll = Enum.map(1..10, fn _ ->
  start = System.monotonic_time(:microsecond)
  Attest.Machine.execute(hs_client, "tailscale debug netmap >/dev/null 2>&1")
  System.monotonic_time(:microsecond) - start
end)

Bench.print_result("railscale: map poll", rs_poll)
Bench.print_result("headscale: map poll", hs_poll)

# ── benchmark: server-side HTTP latency (curl from server itself) ──

IO.puts("\n=== benchmark: HTTP health/endpoint latency (#{n} rounds) ===\n")

rs_http = Bench.bench_cmd(rs_server,
  "curl -so /dev/null -w '%{time_total}' http://127.0.0.1:8080/health 2>&1", n)
hs_http = Bench.bench_cmd(hs_server,
  "curl -so /dev/null -w '%{time_total}' http://127.0.0.1:8080/health 2>&1", n)
Bench.print_result("railscale: HTTP /health", rs_http)
Bench.print_result("headscale: HTTP /health", hs_http)

# ── memory usage ──

IO.puts("\n=== memory usage (RSS) ===\n")

{_, rs_mem} = Attest.Machine.execute(rs_server,
  "ps -C railscale -o rss= 2>&1 | awk '{sum+=$1} END {print sum}'"
)
{_, hs_mem} = Attest.Machine.execute(hs_server,
  "ps -C headscale -o rss= 2>&1 | awk '{sum+=$1} END {print sum}'"
)

rs_kb = case Integer.parse(String.trim(rs_mem)) do
  {n, _} -> n
  _ -> 0
end
hs_kb = case Integer.parse(String.trim(hs_mem)) do
  {n, _} -> n
  _ -> 0
end

IO.puts("  railscale: #{Float.round(rs_kb / 1024, 1)} MB")
IO.puts("  headscale: #{Float.round(hs_kb / 1024, 1)} MB")
IO.puts("  ratio:     #{if hs_kb > 0, do: Float.round(hs_kb / max(rs_kb, 1), 1), else: "?"}x")

IO.puts("\n=== done ===\n")
