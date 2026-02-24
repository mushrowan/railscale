defmodule Check do
  def server_healthy(machine, name) do
    Attest.wait_for_unit(machine, "railscale.service")
    Attest.wait_for_open_port(machine, 8080)

    status = Attest.succeed(machine, "systemctl is-active railscale.service")

    unless String.contains?(status, "active") do
      raise "#{name}: service not active, got #{inspect(status)}"
    end

    # check for errors in logs (warn only, don't fail)
    {code, output} = Attest.Machine.execute(machine, "journalctl -u railscale --no-pager | grep -i ERROR | head -5")

    if code == 0 and String.contains?(output, "ERROR") do
      IO.puts("#{name}: found errors in logs: #{output}")
    end

    IO.puts("#{name}: server healthy")
  end
end

start_all.()

machines = [
  {basic, "basic", "basic server starts"},
  {withapi, "withapi", "server with API enabled starts"},
  {withderp, "withderp", "server with embedded DERP starts"},
  {withdns, "withdns", "server with DNS extra_records starts"}
]

Attest.wait_all(machines, fn {machine, name, label} ->
  IO.puts("--- #{label} ---")
  Check.server_healthy(machine, name)
end)

IO.puts("all smoke tests passed!")
